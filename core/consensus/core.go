package consensus

import (
	"gradeddag/core"
	"gradeddag/crypto"
	"gradeddag/logger"
	"gradeddag/mempool"
	"gradeddag/pool"
	"gradeddag/store"
	"sync"
	"time"
)

const (
	WaveRound = 2
	GradeOne  = 1
	GradeTwo  = 2
)

type Core struct {
	nodeID              core.NodeID
	round               int
	committee           core.Committee
	parameters          core.Parameters
	txpool              *pool.Pool
	transmitor          *core.Transmitor
	sigService          *crypto.SigService
	store               *store.Store
	retriever           *Retriever
	eletor              *Elector
	commitor            *Commitor
	localDAG            *LocalDAG
	loopBackChannel     chan *Block
	grbcCallBackChannel chan *grbcCallBackReq
	cbcCallBackChannel  chan *cbcCallBackReq
	commitChannel       chan<- *Block
	proposedNotify      map[int]*sync.Mutex
	proposedFlag        map[int]struct{}
	grbcInstances       map[int]map[core.NodeID]*GRBC
	cbcInstances        map[int]map[core.NodeID]*CBC

	Mempool            *mempool.Mempool
	mempoolbackchannel chan crypto.Digest
	connectChannel     chan core.Message
	notifyPLoad        chan crypto.Digest

	RpyBlockPendding map[crypto.Digest]struct{}
	LoopBackPendding map[crypto.Digest]struct{}
}

func NewCore(
	nodeID core.NodeID,
	committee core.Committee,
	parameters core.Parameters,
	txpool *pool.Pool,
	transmitor *core.Transmitor,
	store *store.Store,
	sigService *crypto.SigService,
	commitChannel chan<- *Block,

	mempoolbackchannel chan crypto.Digest,
	connectChannel chan core.Message,
	pool *mempool.Mempool,
) *Core {

	loopBackChannel := make(chan *Block, 1_000)
	grbcCallBackChannel := make(chan *grbcCallBackReq, 1_000)
	notifypload := make(chan crypto.Digest, 100)
	corer := &Core{
		nodeID:              nodeID,
		committee:           committee,
		round:               0,
		parameters:          parameters,
		txpool:              txpool,
		transmitor:          transmitor,
		sigService:          sigService,
		store:               store,
		loopBackChannel:     loopBackChannel,
		grbcCallBackChannel: grbcCallBackChannel,
		commitChannel:       commitChannel,
		proposedNotify:      make(map[int]*sync.Mutex),
		grbcInstances:       make(map[int]map[core.NodeID]*GRBC),
		localDAG:            NewLocalDAG(),
		proposedFlag:        make(map[int]struct{}),
		cbcInstances:        make(map[int]map[core.NodeID]*CBC),
		cbcCallBackChannel:  make(chan *cbcCallBackReq, 100),

		Mempool:            pool,
		mempoolbackchannel: mempoolbackchannel,
		connectChannel:     connectChannel,
		notifyPLoad:        notifypload,

		RpyBlockPendding: make(map[crypto.Digest]struct{}),
		LoopBackPendding: make(map[crypto.Digest]struct{}),
	}

	corer.retriever = NewRetriever(nodeID, store, transmitor, sigService, parameters, loopBackChannel)
	corer.eletor = NewElector(sigService, committee)
	corer.commitor = NewCommitor(corer.eletor, corer.localDAG, store, commitChannel, committee.Size(), connectChannel, notifypload)

	return corer
}

func storeBlock(store *store.Store, block *Block) error {
	key := block.Hash()
	if val, err := block.Encode(); err != nil {
		return err
	} else {
		store.Write(key[:], val)
		return nil
	}
}

func GetPayload(s *store.Store, digest crypto.Digest) (*mempool.Payload, error) {
	value, err := s.Read(digest[:])

	if err == store.ErrNotFoundKey {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	b := &mempool.Payload{}
	if err := b.Decode(value); err != nil {
		return nil, err
	}
	return b, err
}

func getBlock(store *store.Store, digest crypto.Digest) (*Block, error) {
	block := &Block{}
	data, err := store.Read(digest[:])
	if err != nil {
		return nil, err
	}
	if err := block.Decode(data); err != nil {
		return nil, err
	}
	return block, nil
}

func (corer *Core) getGRBCInstance(node core.NodeID, round int) *GRBC {
	instances := corer.grbcInstances[round]
	if instances == nil {
		instances = make(map[core.NodeID]*GRBC)
	}
	if _, ok := instances[node]; !ok {
		instances[node] = NewGRBC(corer, node, round, corer.grbcCallBackChannel)
	}
	corer.grbcInstances[round] = instances
	return instances[node]
}

func (corer *Core) getCBCInstance(node core.NodeID, round int) *CBC {
	instances, ok := corer.cbcInstances[round]
	if !ok {
		instances = map[core.NodeID]*CBC{}
		corer.cbcInstances[round] = instances
	}
	instance, ok := instances[node]
	if !ok {
		instance = NewCBC(corer, node, round, corer.cbcCallBackChannel)
		instances[node] = instance
	}
	return instance
}

func (corer *Core) checkReference(block *Block) (bool, []crypto.Digest) {
	var temp []crypto.Digest
	for d := range block.Reference {
		temp = append(temp, d)
	}
	ok, missDeigest := corer.localDAG.IsReceived(temp...)
	return ok, missDeigest
}

func (corer *Core) checkPayloads(block *Block) mempool.VerifyStatus {
	msg := &mempool.VerifyBlockMsg{
		Proposer:           block.Author,
		Epoch:              int64(block.Round),
		Payloads:           block.PayLoads,
		ConsensusBlockHash: block.Hash(),
		Sender:             make(chan mempool.VerifyStatus),
	}
	corer.connectChannel <- msg
	status := <-msg.Sender
	return status
}

/*********************************Protocol***********************************************/
func (corer *Core) generatorBlock(round int) *Block {
	logger.Debug.Printf("procesing generatorBlock round %d \n", round)

	var block *Block
	if _, ok := corer.proposedFlag[round]; !ok {
		referencechan := make(chan []crypto.Digest)
		msg := &mempool.MakeConsensusBlockMsg{
			Payloads: referencechan,
		}
		corer.connectChannel <- msg
		payloads := <-referencechan
		// GRBC round
		if round%WaveRound == 0 {
			if round == 0 {
				block = &Block{
					Author:    corer.nodeID,
					Round:     round,
					PayLoads:  payloads,
					Reference: make(map[crypto.Digest]core.NodeID),
					TimeStamp: time.Now().Unix(),
				}
			} else {
				reference := corer.localDAG.GetRoundReceivedBlock(round - 1)
				if len(reference) >= corer.committee.HightThreshold() {
					block = &Block{
						Author:    corer.nodeID,
						Round:     round,
						PayLoads:  payloads,
						Reference: reference,
						TimeStamp: time.Now().Unix(),
					}
				}
			}
		} else { // PBC round
			_, grade2nums := corer.localDAG.GetRoundReceivedBlockNums(round - 1)
			if grade2nums >= corer.committee.HightThreshold() {
				reference := corer.localDAG.GetRoundReceivedBlock(round - 1)
				block = &Block{
					Author:    corer.nodeID,
					Round:     round,
					PayLoads:  payloads,
					Reference: reference,
					TimeStamp: time.Now().Unix(),
				}
			}
		}
	}

	if block != nil {
		corer.proposedFlag[round] = struct{}{}

		logger.Info.Printf("create Block round %d node %d \n", block.Round, block.Author)

	}

	return block
}

func (corer *Core) handleGRBCPropose(propose *GRBCProposeMsg) error {
	logger.Debug.Printf("procesing grbc propose round %d node %d \n", propose.Round, propose.Author)

	//Step 1: verify signature
	if !propose.Verify(corer.committee) {
		return ErrSignature(propose.MsgType(), propose.Round, int(propose.Author))
	}

	//如果已经收到了2f+1个grade2的grbc，就停止投票
	if _, g2 := corer.localDAG.GetRoundReceivedBlockNums(propose.Round); g2 >= corer.committee.HightThreshold() {
		return nil
	}

	//Step 2: store Block
	if err := storeBlock(corer.store, propose.B); err != nil {
		return err
	}

	//Step 3: check reference
	if ok, miss := corer.checkReference(propose.B); !ok {
		//retrieve miss block
		corer.retriever.requestBlocks(miss, propose.Author, propose.B.Hash())

		if status := corer.checkPayloads(propose.B); status != mempool.OK {
			logger.Debug.Printf("[round-%d-node-%d] not receive all payloads\n ", propose.Round, propose.Author)
		}
		return ErrReference(propose.MsgType(), propose.Round, int(propose.Author))
	}

	//Step 4:check payloads
	if status := corer.checkPayloads(propose.B); status != mempool.OK {
		return ErrLossPayloads(propose.Round, int(propose.Author))
	}

	//Step 5: process
	instance := corer.getGRBCInstance(propose.Author, propose.Round)
	go instance.processPropose(propose.B)

	return nil
}

func (corer *Core) handleEcho(echo *EchoMsg) error {
	logger.Debug.Printf("procesing grbc echo round %d node %d \n", echo.Round, echo.Proposer)

	//Step 1: verify signature
	if !echo.Verify(corer.committee) {
		return ErrSignature(echo.MsgType(), echo.Round, int(echo.Author))
	}

	instance := corer.getGRBCInstance(echo.Proposer, echo.Round)
	go instance.processEcho(echo)

	return nil
}

func (corer *Core) handleReady(ready *ReadyMsg) error {
	logger.Debug.Printf("procesing grbc ready round %d node %d \n", ready.Round, ready.Proposer)

	//Step 1: verify signature
	if !ready.Verify(corer.committee) {
		return ErrSignature(ready.MsgType(), ready.Round, int(ready.Author))
	}

	instance := corer.getGRBCInstance(ready.Proposer, ready.Round)
	go instance.processReady(ready)

	return nil
}

func (corer *Core) handleCBCPropose(propose *CBCProposeMsg) error {
	logger.Debug.Printf("procesing cbc propose round %d node %d \n", propose.Round, propose.Author)

	//Step 1: verify signature
	if !propose.Verify(corer.committee) {
		return ErrSignature(propose.MsgType(), propose.Round, int(propose.Author))
	}

	//Step 2: store Block
	if err := storeBlock(corer.store, propose.B); err != nil {
		return err
	}

	// Step 3: check reference
	// if ok, miss := corer.checkReference(propose.B); !ok {
	// 	//retrieve miss block
	// 	corer.retriever.requestBlocks(miss, propose.Author, propose.B.Hash())
	// 	if (propose.Round-1)%WaveRound != 0 { //如果前一轮是一个PB Round，必须等收到区块后开始投票
	// 		return ErrReference(propose.MsgType(), propose.Round, int(propose.Author))
	// 	}
	// }

	//Step 4:check payloads
	if status := corer.checkPayloads(propose.B); status != mempool.OK {
		return ErrLossPayloads(propose.Round, int(propose.Author))
	}

	//Step 5
	go corer.getCBCInstance(propose.Author, propose.Round).ProcessProposal(propose)

	return nil
}

func (corer *Core) handleCBCVote(vote *CBCVoteMsg) error {
	logger.Debug.Printf("procesing cbc vote proposer %d round %d author %d \n", vote.Proposer, vote.Round, vote.Author)
	//Step 1: verify signature
	if !vote.Verify(corer.committee) {
		return ErrSignature(vote.MsgType(), vote.Round, int(vote.Author))
	}

	go corer.getCBCInstance(vote.Proposer, vote.Round).ProcessVote(vote)

	return nil
}

func (corer *Core) handleOutPut(round int, node core.NodeID, digest crypto.Digest, references map[crypto.Digest]core.NodeID) error {
	logger.Debug.Printf("procesing output round %d node %d \n", round, node)

	corer.localDAG.ReceiveBlock(round, node, digest, references)

	if n, grade2nums := corer.localDAG.GetRoundReceivedBlockNums(round); n >= corer.committee.HightThreshold() {
		if round%WaveRound == 0 {
			if grade2nums >= corer.committee.HightThreshold() {
				corer.advanceRound(round + 1)
				// if _, ok := corer.proposedNotify[round+1]; !ok {
				// 	corer.proposedNotify[round+1] = &sync.Mutex{} // first
				// 	//timeout
				// 	time.AfterFunc(time.Millisecond*time.Duration(corer.parameters.NetwrokDelay), func() {
				// 		mu := corer.proposedNotify[round+1]
				// 		if mu.TryLock() {
				// 			corer.advanceRound(round + 1)
				// 		}
				// 	})
				// }
				// if grade2nums == corer.committee.Size() {
				// 	mu := corer.proposedNotify[round+1] // second
				// 	if mu.TryLock() {
				// 		corer.advanceRound(round + 1)
				// 	}
				// }
			}

		} else {
			return corer.advanceRound(round + 1)
		}
	}

	return nil
}

func (corer *Core) advanceRound(round int) error {

	logger.Debug.Printf("procesing advance round %d \n", round)

	if block := corer.generatorBlock(round); block != nil {
		if round%WaveRound == 0 {
			if propose, err := NewGRBCProposeMsg(corer.nodeID, round, block, corer.sigService); err != nil {
				return err
			} else {
				corer.transmitor.Send(corer.nodeID, core.NONE, propose)
				time.Sleep(time.Millisecond * time.Duration(corer.parameters.MinBlockDelay))
				corer.transmitor.RecvChannel() <- propose
			}
		} else {
			if propose, err := NewCBCProposeMsg(corer.nodeID, round, block, corer.sigService); err != nil {
				return err
			} else {
				corer.transmitor.Send(corer.nodeID, core.NONE, propose)
				time.Sleep(time.Millisecond * time.Duration(corer.parameters.MinBlockDelay))
				// invoke elect phase
				corer.transmitor.RecvChannel() <- propose
				corer.invokeElect(round)
			}
		}
	}

	return nil
}

func (corer *Core) invokeElect(round int) error {
	if round%WaveRound == 1 {
		elect, err := NewElectMsg(
			corer.nodeID,
			round,
			corer.sigService,
		)
		if err != nil {
			return err
		}
		corer.transmitor.Send(corer.nodeID, core.NONE, elect)
		corer.transmitor.RecvChannel() <- elect
	}
	return nil
}

func (corer *Core) handleElect(elect *ElectMsg) error {
	logger.Debug.Printf("procesing elect wave %d node %d \n", elect.Round/WaveRound, elect.Author)

	if leader, err := corer.eletor.Add(elect); err != nil {
		return err
	} else if leader != core.NONE {
		grade := corer.localDAG.GetGrade(elect.Round-1, int(leader))
		logger.Debug.Printf("Elector: wave %d leader %d grade %d \n", elect.Round/WaveRound, leader, grade)
		//is grade two?
		if grade == GradeTwo {
			corer.commitor.NotifyToCommit(elect.Round / WaveRound)
		}

	}

	return nil
}

func (corer *Core) handleRequestBlock(request *RequestBlockMsg) error {
	logger.Debug.Println("procesing block request")

	//Step 1: verify signature
	if !request.Verify(corer.committee) {
		return ErrSignature(request.MsgType(), -1, int(request.Author))
	}

	go corer.retriever.processRequest(request)

	return nil
}

func (corer *Core) handleReplyBlock(reply *ReplyBlockMsg) error {
	logger.Debug.Println("procesing block reply")

	//Step 1: verify signature
	if !reply.Verify(corer.committee) {
		return ErrSignature(reply.MsgType(), -1, int(reply.Author))
	}

	for _, block := range reply.Blocks {
		if block.Round%WaveRound == 0 {
			corer.localDAG.UpdateGrade(block.Round, int(block.Author), GradeOne)
		}

		//maybe execute more one
		storeBlock(corer.store, block)

		//status := corer.checkPayloads(block)
		// if status != mempool.OK {
		// 	if _, ok := corer.RpyBlockPendding[block.Hash()]; !ok {
		// 		corer.RpyBlockPendding[block.Hash()] = struct{}{}
		// 	}
		// 	continue
		// }

		corer.handleOutPut(block.Round, block.Author, block.Hash(), block.Reference)
	}

	go corer.retriever.processReply(reply)

	return nil
}

func (corer *Core) handleLoopBack(block *Block) error {
	logger.Debug.Printf("procesing block loop back round %d node %d \n", block.Round, block.Author)
	status := corer.checkPayloads(block)
	if status != mempool.OK {
		corer.LoopBackPendding[block.Hash()] = struct{}{}
		return ErrLossPayloads(block.Round, int(block.Author))
	}
	//GRBC round
	if block.Round%WaveRound == 0 {
		instance := corer.getGRBCInstance(block.Author, block.Round)
		go instance.processPropose(block)
	} else {
		return corer.handleOutPut(block.Round, block.Author, block.Hash(), block.Reference)
	}

	return nil
}

// mempool
func (corer *Core) handleMLoopBack(digest crypto.Digest) error {
	corer.notifyPLoad <- digest

	//re output
	block, _ := getBlock(corer.store, digest)
	if ok, _ := corer.checkReference(block); ok {
		if _, ok := corer.RpyBlockPendding[digest]; ok {
			delete(corer.RpyBlockPendding, digest)
			corer.handleOutPut(block.Round, block.Author, block.Hash(), block.Reference)
		}
		if _, ok := corer.LoopBackPendding[digest]; ok {
			delete(corer.LoopBackPendding, digest)
			corer.handleLoopBack(block)
		}

	}

	return nil
}

func (corer *Core) handleGRBCCallBack(req *grbcCallBackReq) error {
	logger.Debug.Printf("procesing grbc block call back round %d node %d \n", req.round, req.nodeID)

	//Update grade
	corer.localDAG.UpdateGrade(req.round, int(req.nodeID), req.grade)

	//try to advance round
	if req.tag == UpdateGrade {
		return corer.advanceRound(req.round + 1)
	} else if req.tag == NotifyOutPut {
		return corer.handleOutPut(req.round, req.nodeID, req.digest, req.reference)
	}

	return nil
}

func (corer *Core) handleCBCCallBack(req *cbcCallBackReq) error {
	logger.Debug.Printf("procesing cbc block call back round %d node %d \n", req.Round, req.Proposer)
	return corer.handleOutPut(req.Round, req.Proposer, req.BlockHash, req.Reference)
}

func (corer *Core) Run() {

	go corer.Mempool.Run()

	if corer.nodeID >= core.NodeID(corer.parameters.Faults) {
		//first propose
		block := corer.generatorBlock(0)
		if propose, err := NewGRBCProposeMsg(corer.nodeID, 0, block, corer.sigService); err != nil {
			logger.Error.Println(err)
			panic(err)
		} else {
			corer.transmitor.Send(corer.nodeID, core.NONE, propose)
			corer.transmitor.RecvChannel() <- propose
		}

		for {
			var err error
			select {
			case msg := <-corer.transmitor.RecvChannel():
				{
					switch msg.MsgType() {

					case GRBCProposeType:
						err = corer.handleGRBCPropose(msg.(*GRBCProposeMsg))
					case EchoType:
						err = corer.handleEcho(msg.(*EchoMsg))
					case ReadyType:
						err = corer.handleReady(msg.(*ReadyMsg))
					case CBCProposeType:
						err = corer.handleCBCPropose(msg.(*CBCProposeMsg))
					case CBCVoteType:
						err = corer.handleCBCVote(msg.(*CBCVoteMsg))
					case ElectType:
						err = corer.handleElect(msg.(*ElectMsg))
					case RequestBlockType:
						err = corer.handleRequestBlock(msg.(*RequestBlockMsg))
					case ReplyBlockType:
						err = corer.handleReplyBlock(msg.(*ReplyBlockMsg))
					}
				}

			case block := <-corer.loopBackChannel:
				{
					err = corer.handleLoopBack(block)
				}
			case cbReq := <-corer.grbcCallBackChannel:
				{
					err = corer.handleGRBCCallBack(cbReq)
				}
			case cbReq := <-corer.cbcCallBackChannel:
				{
					err = corer.handleCBCCallBack(cbReq)
				}
			case mblock := <-corer.mempoolbackchannel:
				{
					err = corer.handleMLoopBack(mblock)
				}
			}

			if err != nil {
				logger.Warn.Println(err)
			}

		}
	}
}
