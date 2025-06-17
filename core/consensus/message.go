package consensus

import (
	"bytes"
	"encoding/gob"
	"gradeddag/core"
	"gradeddag/crypto"
	"reflect"
	"strconv"
)

type Block struct {
	Author    core.NodeID
	Round     int
	PayLoads  []crypto.Digest
	Reference map[crypto.Digest]core.NodeID
	TimeStamp int64
}

func (b *Block) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Block) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(b); err != nil {
		return err
	}
	return nil
}

func (b *Block) Hash() crypto.Digest {

	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(b.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(b.Round), 2))
	hasher.Add(strconv.AppendInt(nil, int64(b.TimeStamp), 10))
	for _, p := range b.PayLoads {
		hasher.Add(p[:])
	}
	// for _, tx := range b.Batch.Txs {
	// 	hasher.Add(tx)
	// }
	// for d, id := range b.Reference {
	// 	hasher.Add(d[:])
	// 	hasher.Add(strconv.AppendInt(nil, int64(id), 2))
	// }

	return hasher.Sum256(nil)
}

// ProposeMsg
type GRBCProposeMsg struct {
	Author    core.NodeID
	Round     int
	B         *Block
	Signature crypto.Signature
}

func NewGRBCProposeMsg(
	Author core.NodeID,
	Round int,
	B *Block,
	sigService *crypto.SigService,
) (*GRBCProposeMsg, error) {

	msg := &GRBCProposeMsg{
		Author: Author,
		Round:  Round,
		B:      B,
	}

	if sig, err := sigService.RequestSignature(msg.Hash()); err != nil {
		return nil, err
	} else {
		msg.Signature = sig
		return msg, nil
	}
}

func (msg *GRBCProposeMsg) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *GRBCProposeMsg) Hash() crypto.Digest {

	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	digest := msg.B.Hash()
	hasher.Add(digest[:])
	return hasher.Sum256(nil)
}

func (msg *GRBCProposeMsg) MsgType() int {
	return GRBCProposeType
}

func (msg *GRBCProposeMsg) Module() string {
	return "consensus"
}

// EchoMsg
type EchoMsg struct {
	Author    core.NodeID
	Proposer  core.NodeID
	BlockHash crypto.Digest
	Round     int
	Signature crypto.Signature
}

func NewEchoMsg(
	Author core.NodeID,
	Proposer core.NodeID,
	BlockHash crypto.Digest,
	Round int,
	sigService *crypto.SigService,
) (*EchoMsg, error) {
	msg := &EchoMsg{
		Author:    Author,
		Proposer:  Proposer,
		BlockHash: BlockHash,
		Round:     Round,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *EchoMsg) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *EchoMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Proposer), 2))
	hasher.Add(msg.BlockHash[:])
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	return hasher.Sum256(nil)
}

func (msg *EchoMsg) MsgType() int {
	return EchoType
}

func (msg *EchoMsg) Module() string {
	return "consensus"
}

// ReadyMsg
type ReadyMsg struct {
	Author    core.NodeID
	Proposer  core.NodeID
	BlockHash crypto.Digest
	Round     int
	Signature crypto.Signature
}

func NewReadyMsg(
	Author core.NodeID,
	Proposer core.NodeID,
	BlockHash crypto.Digest,
	Round int,
	sigService *crypto.SigService,
) (*ReadyMsg, error) {
	msg := &ReadyMsg{
		Author:    Author,
		Proposer:  Proposer,
		BlockHash: BlockHash,
		Round:     Round,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *ReadyMsg) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *ReadyMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Proposer), 2))
	hasher.Add(msg.BlockHash[:])
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	return hasher.Sum256(nil)
}

func (msg *ReadyMsg) MsgType() int {
	return ReadyType
}

func (msg *ReadyMsg) Module() string {
	return "consensus"
}

// CBCProposeMsg
type CBCProposeMsg struct {
	Author    core.NodeID
	Round     int
	B         *Block
	Signature crypto.Signature
}

func NewCBCProposeMsg(
	Author core.NodeID,
	Round int,
	B *Block,
	sigService *crypto.SigService,
) (*CBCProposeMsg, error) {

	msg := &CBCProposeMsg{
		Author: Author,
		Round:  Round,
		B:      B,
	}

	if sig, err := sigService.RequestSignature(msg.Hash()); err != nil {
		return nil, err
	} else {
		msg.Signature = sig
		return msg, nil
	}
}

func (msg *CBCProposeMsg) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *CBCProposeMsg) Hash() crypto.Digest {

	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	digest := msg.B.Hash()
	hasher.Add(digest[:])
	return hasher.Sum256(nil)
}

func (msg *CBCProposeMsg) MsgType() int {
	return CBCProposeType
}

func (msg *CBCProposeMsg) Module() string {
	return "consensus"
}

type CBCVoteMsg struct {
	Author    core.NodeID
	Proposer  core.NodeID
	BlockHash crypto.Digest
	Round     int
	Signature crypto.Signature
}

func NewCBCVoteMsg(Author core.NodeID, B *Block, sigService *crypto.SigService) (*CBCVoteMsg, error) {
	vote := &CBCVoteMsg{
		Author:    Author,
		Proposer:  B.Author,
		BlockHash: B.Hash(),
		Round:     B.Round,
	}
	vote.Signature, _ = sigService.RequestSignature(vote.Hash())
	return vote, nil
}

func (v *CBCVoteMsg) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *CBCVoteMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Proposer), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Round), 2))
	hasher.Add(v.BlockHash[:])
	return hasher.Sum256(nil)
}

func (v *CBCVoteMsg) MsgType() int {
	return CBCVoteType
}

func (msg *CBCVoteMsg) Module() string {
	return "consensus"
}

// ElectMsg
type ElectMsg struct {
	Author   core.NodeID
	Round    int
	SigShare crypto.SignatureShare
}

func NewElectMsg(Author core.NodeID, Round int, sigService *crypto.SigService) (*ElectMsg, error) {
	msg := &ElectMsg{
		Author: Author,
		Round:  Round,
	}
	share, err := sigService.RequestTsSugnature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.SigShare = share

	return msg, nil
}

func (msg *ElectMsg) Verify() bool {
	return msg.SigShare.Verify(msg.Hash())
}

func (msg *ElectMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	// hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	return hasher.Sum256(nil)
}

func (msg *ElectMsg) MsgType() int {
	return ElectType
}
func (msg *ElectMsg) Module() string {
	return "consensus"
}

// RequestBlock
type RequestBlockMsg struct {
	Author    core.NodeID
	MissBlock []crypto.Digest
	Signature crypto.Signature
	ReqID     int
	Ts        int64
}

func NewRequestBlock(
	Author core.NodeID,
	MissBlock []crypto.Digest,
	ReqID int,
	Ts int64,
	sigService *crypto.SigService,
) (*RequestBlockMsg, error) {
	msg := &RequestBlockMsg{
		Author:    Author,
		MissBlock: MissBlock,
		ReqID:     ReqID,
		Ts:        Ts,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *RequestBlockMsg) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *RequestBlockMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.ReqID), 2))
	for _, d := range msg.MissBlock {
		hasher.Add(d[:])
	}
	return hasher.Sum256(nil)
}

func (msg *RequestBlockMsg) MsgType() int {
	return RequestBlockType
}

func (msg *RequestBlockMsg) Module() string {
	return "consensus"
}

// ReplyBlockMsg
type ReplyBlockMsg struct {
	Author    core.NodeID
	Blocks    []*Block
	ReqID     int
	Signature crypto.Signature
}

func NewReplyBlockMsg(Author core.NodeID, B []*Block, ReqID int, sigService *crypto.SigService) (*ReplyBlockMsg, error) {
	msg := &ReplyBlockMsg{
		Author: Author,
		Blocks: B,
		ReqID:  ReqID,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *ReplyBlockMsg) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *ReplyBlockMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.ReqID), 2))
	return hasher.Sum256(nil)
}

func (msg *ReplyBlockMsg) MsgType() int {
	return ReplyBlockType
}

func (msg *ReplyBlockMsg) Module() string {
	return "consensus"
}

type LoopBackMsg struct {
	BlockHash crypto.Digest
}

func (msg *LoopBackMsg) Hash() crypto.Digest {
	return crypto.NewHasher().Sum256(msg.BlockHash[:])
}

func (msg *LoopBackMsg) MsgType() int {
	return LoopBackType
}

func (msg *LoopBackMsg) Module() string {
	return "consensus"
}

const (
	GRBCProposeType int = iota
	EchoType
	ReadyType
	ElectType
	CBCProposeType
	CBCVoteType
	RequestBlockType
	ReplyBlockType
	LoopBackType
	TotalNums
)

var DefaultMsgTypes = map[int]reflect.Type{
	GRBCProposeType:  reflect.TypeOf(GRBCProposeMsg{}),
	EchoType:         reflect.TypeOf(EchoMsg{}),
	ReadyType:        reflect.TypeOf(ReadyMsg{}),
	ElectType:        reflect.TypeOf(ElectMsg{}),
	CBCProposeType:   reflect.TypeOf(CBCProposeMsg{}),
	CBCVoteType:      reflect.TypeOf(CBCVoteMsg{}),
	RequestBlockType: reflect.TypeOf(RequestBlockMsg{}),
	ReplyBlockType:   reflect.TypeOf(ReplyBlockMsg{}),
	LoopBackType:     reflect.TypeOf(LoopBackMsg{}),
}
