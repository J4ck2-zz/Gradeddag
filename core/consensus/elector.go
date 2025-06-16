package consensus

import (
	"gradeddag/crypto"
	"gradeddag/core"
	"sync"
)

type Aggregator struct {
	elects []*ElectMsg
	used   map[core.NodeID]struct{}
}

func (a *Aggregator) Append(elect *ElectMsg, committee core.Committee, sigService *crypto.SigService) (core.NodeID, error) {
	if _, ok := a.used[elect.Author]; ok {
		return core.NONE, ErrUsedElect(ElectType, elect.Round, int(elect.Author))
	} else {
		a.used[elect.Author] = struct{}{}
		a.elects = append(a.elects, elect)
		if len(a.elects) == committee.HightThreshold() {
			var shares []crypto.SignatureShare
			for _, e := range a.elects {
				shares = append(shares, e.SigShare)
			}
			qc, err := crypto.CombineIntactTSPartial(shares, sigService.ShareKey, elect.Hash())
			if err != nil {
				return core.NONE, err
			}
			var randint core.NodeID = 0
			for i := 0; i < 4; i++ {
				randint = randint<<8 + core.NodeID(qc[i])
			}
			return randint % core.NodeID(committee.Size()), nil
		}
	}
	return core.NONE, nil
}

type Elector struct {
	mu         *sync.RWMutex
	leaders    map[int]core.NodeID
	aggregator map[int]*Aggregator
	sigService *crypto.SigService
	committee  core.Committee
}

func NewElector(sigService *crypto.SigService, committee core.Committee) *Elector {
	return &Elector{
		mu:         &sync.RWMutex{},
		leaders:    make(map[int]core.NodeID),
		aggregator: make(map[int]*Aggregator),
		sigService: sigService,
		committee:  committee,
	}
}

func (e *Elector) Add(elect *ElectMsg) (core.NodeID, error) {

	waveNum := elect.Round / WaveRound
	a, ok := e.aggregator[waveNum]
	if !ok {
		a = &Aggregator{
			used:   make(map[core.NodeID]struct{}),
			elects: make([]*ElectMsg, 0),
		}
		e.aggregator[waveNum] = a
	}
	id, err := a.Append(elect, e.committee, e.sigService)
	if err == nil && id != core.NONE {
		e.mu.Lock()
		e.leaders[waveNum] = id
		e.mu.Unlock()
	}
	return id, err
}

func (e *Elector) GetLeader(waveNum int) core.NodeID {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if leader, ok := e.leaders[waveNum]; ok {
		return leader
	} else {
		return core.NONE
	}
}
