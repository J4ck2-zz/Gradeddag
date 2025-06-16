package consensus

import (
	"gradeddag/crypto"
	"gradeddag/logger"
	"gradeddag/store"
	"gradeddag/core"
	"gradeddag/mempool"
	"sync"
)

type LocalDAG struct {
	muBlock      *sync.RWMutex
	blockDigests map[crypto.Digest]core.NodeID // store hash of block that has received
	muDAG        *sync.RWMutex
	localDAG     map[int]map[core.NodeID]crypto.Digest // local DAG
	edgesDAG     map[int]map[core.NodeID]map[crypto.Digest]core.NodeID
	muGrade      *sync.RWMutex
	gradeDAG     map[int]map[core.NodeID]int
}

func NewLocalDAG() *LocalDAG {
	return &LocalDAG{
		muBlock:      &sync.RWMutex{},
		muDAG:        &sync.RWMutex{},
		muGrade:      &sync.RWMutex{},
		blockDigests: make(map[crypto.Digest]core.NodeID),
		localDAG:     make(map[int]map[core.NodeID]crypto.Digest),
		gradeDAG:     make(map[int]map[core.NodeID]int),
		edgesDAG:     make(map[int]map[core.NodeID]map[crypto.Digest]core.NodeID),
	}
}

// IsReceived: digests is received ?
func (local *LocalDAG) IsReceived(digests ...crypto.Digest) (bool, []crypto.Digest) {
	local.muBlock.RLock()
	defer local.muBlock.RUnlock()

	var miss []crypto.Digest
	var flag bool = true
	for _, d := range digests {
		if _, ok := local.blockDigests[d]; !ok {
			miss = append(miss, d)
			flag = false
		}
	}

	return flag, miss
}

func (local *LocalDAG) ReceiveBlock(round int, node core.NodeID, digest crypto.Digest, references map[crypto.Digest]core.NodeID) {
	local.muBlock.Lock()
	local.blockDigests[digest] = node
	local.muBlock.Unlock()

	local.muDAG.Lock()
	vslot, ok := local.localDAG[round]
	eslot := local.edgesDAG[round]
	if !ok {
		vslot = make(map[core.NodeID]crypto.Digest)
		eslot = make(map[core.NodeID]map[crypto.Digest]core.NodeID)
		local.localDAG[round] = vslot
		local.edgesDAG[round] = eslot
	}
	vslot[node] = digest
	eslot[node] = references

	local.muDAG.Unlock()
}

func (local *LocalDAG) GetRoundReceivedBlockNums(round int) (nums, grade2nums int) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	local.muGrade.RLock()
	defer local.muGrade.RUnlock()

	nums = len(local.localDAG[round])
	if round%WaveRound == 0 {
		for _, g := range local.gradeDAG[round] {
			if g == GradeTwo {
				grade2nums++
			}
		}
	}

	return
}

func (local *LocalDAG) GetReceivedBlock(round int, node core.NodeID) (crypto.Digest, bool) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	if slot, ok := local.localDAG[round]; ok {
		d, ok := slot[node]
		return d, ok
	}
	return crypto.Digest{}, false
}

func (local *LocalDAG) GetReceivedBlockReference(round int, node core.NodeID) (map[crypto.Digest]core.NodeID, bool) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	if slot, ok := local.edgesDAG[round]; ok {
		reference, ok := slot[node]
		return reference, ok
	}
	return nil, false
}

func (local *LocalDAG) GetRoundReceivedBlock(round int) (digests map[crypto.Digest]core.NodeID) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	digests = make(map[crypto.Digest]core.NodeID)
	for id, d := range local.localDAG[round] {
		digests[d] = id
	}

	return digests
}

func (local *LocalDAG) GetGrade(round, node int) (grade int) {
	if round%WaveRound == 0 {
		local.muGrade.RLock()
		if slot, ok := local.gradeDAG[round]; !ok {
			return 0
		} else {
			grade = slot[core.NodeID(node)]
		}
		local.muGrade.RUnlock()
	}
	return
}

func (local *LocalDAG) UpdateGrade(round, node, grade int) {
	if round%WaveRound == 0 {
		local.muGrade.Lock()

		slot, ok := local.gradeDAG[round]
		if !ok {
			slot = make(map[core.NodeID]int)
			local.gradeDAG[round] = slot
		}
		if grade > slot[core.NodeID(node)] {
			slot[core.NodeID(node)] = grade
		}

		local.muGrade.Unlock()
	}
}

type Commitor struct {
	elector       *Elector
	commitChannel chan<- *Block
	localDAG      *LocalDAG
	commitBlocks  map[crypto.Digest]struct{}
	curWave       int
	notify        chan int
	inner         chan crypto.Digest
	store         *store.Store
	N             int

	//mempool    *mempool.Mempool
	connectChannel  chan core.Message
	pendingPayloads map[crypto.Digest]chan struct{} // digest -> waiting channel
	muPending       *sync.RWMutex
	notifyPload     chan crypto.Digest
}

func NewCommitor(electot *Elector, localDAG *LocalDAG, store *store.Store, commitChannel chan<- *Block, N int,mc chan core.Message, notify chan crypto.Digest) *Commitor {
	c := &Commitor{
		elector:       electot,
		localDAG:      localDAG,
		commitChannel: commitChannel,
		commitBlocks:  make(map[crypto.Digest]struct{}),
		curWave:       -1,
		notify:        make(chan int, 100),
		store:         store,
		inner:         make(chan crypto.Digest),
		N:             N,

		connectChannel: mc,
		notifyPload: notify,
		pendingPayloads: make(map[crypto.Digest]chan struct{}),
		muPending:       &sync.RWMutex{},
	}
	go c.run()
	return c
}

func (c *Commitor) run() {

	go func() {
		for digest := range c.inner {
			if block, err := getBlock(c.store, digest); err != nil {
				logger.Warn.Println(err)
			} else {
				flag := false
				for _, d := range block.PayLoads {
					payload, err := GetPayload(c.store, d)
					if err != nil {
						logger.Debug.Printf("miss payload round %d node %d\n", block.Round, block.Author)
						//  1. 向网络请求缺失 payload

						msg := &mempool.VerifyBlockMsg{
							Proposer:           block.Author,
							Epoch:              int64(block.Round),
							Payloads:           block.PayLoads,
							ConsensusBlockHash: block.Hash(),
							Sender:             make(chan mempool.VerifyStatus),
						}

						c.connectChannel <- msg
						status := <-msg.Sender
						if status != mempool.OK {
							//  2. 等待 payload 补全（阻塞等待）

							c.waitForPayload(digest)
							logger.Debug.Printf("receive payload by verify \n")
						}
						payload, _ = GetPayload(c.store, d)
					}
					if payload.Batch.ID != -1 {
						flag = true
						logger.Info.Printf("commit batch %d \n", payload.Batch.ID)
					}

				}
				c.commitChannel <- block
				if flag {
					logger.Info.Printf("commit Block round %d node %d \n", block.Round, block.Author)
				}
			}
		}
	}()

	go func() {
		for digest := range c.notifyPload {
			c.muPending.RLock()
			if ch, ok := c.pendingPayloads[digest]; ok {
				select {
				case ch <- struct{}{}: // 通知已经到达
				default: // 防止阻塞，如果已经有人写过了就跳过
				}
			}
			c.muPending.RUnlock()
		}
	}()

	for num := range c.notify {
		if num > c.curWave {
			if leader := c.elector.GetLeader(num); leader != core.NONE {

				var leaderQ [][2]int
				leaderQ = append(leaderQ, [2]int{int(leader), num * 2})
				for i := num - 1; i > c.curWave; i-- {
					if node := c.elector.GetLeader(i); node != core.NONE {
						leaderQ = append(leaderQ, [2]int{int(node), i * 2})
					}
				}
				c.commitLeaderQueue(leaderQ)
				c.curWave = num

			}
		}
	}
}

func (c *Commitor) waitForPayload(digest crypto.Digest) {
	c.muPending.Lock()
	ch, ok := c.pendingPayloads[digest]
	if !ok {
		ch = make(chan struct{}, 1)
		c.pendingPayloads[digest] = ch
	}
	c.muPending.Unlock()
	// 阻塞等待直到 payload 被收到并写入此通道
	<-ch
	logger.Debug.Printf("channel receive \n")
	c.muPending.Lock()
	delete(c.pendingPayloads, digest)
	c.muPending.Unlock()

}

func (c *Commitor) commitLeaderQueue(q [][2]int) {

	nextRound := c.curWave * 2
	for i := len(q) - 1; i >= 0; i-- {
		leader, round := q[i][0], q[i][1]
		var sortC []crypto.Digest
		var (
			qDigest []crypto.Digest
			qNode   []core.NodeID
		)
		if block, ok := c.localDAG.GetReceivedBlock(round, core.NodeID(leader)); !ok {
			logger.Error.Println("commitor : not received block")
			continue
		} else {
			qDigest = append(qDigest, block)
			qNode = append(qNode, core.NodeID(leader))
			for len(qDigest) > 0 && round >= nextRound {
				n := len(qDigest)
				for n > 0 {
					block := qDigest[0]
					node := qNode[0]
					if _, ok := c.commitBlocks[block]; !ok {
						sortC = append(sortC, block)       // seq commit vector
						c.commitBlocks[block] = struct{}{} // commit flag

						if ref, ok := c.localDAG.GetReceivedBlockReference(round, node); !ok {
							logger.Error.Println("commitor : not received block reference")
						} else {
							for digest, node := range ref {
								qDigest = append(qDigest, digest)
								qNode = append(qNode, node)
							}
						}
					}
					qDigest = qDigest[1:]
					qNode = qNode[1:]
					n--
				} //for
				round--
			} //for
		}

		for i := len(sortC) - 1; i >= 0; i-- {
			c.inner <- sortC[i] // SeqCommit
		}
		nextRound = q[i][1]
	} //for
}

func (c *Commitor) NotifyToCommit(waveNum int) {
	c.notify <- waveNum
}
