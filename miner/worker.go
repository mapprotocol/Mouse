// Copyright 2015 The mouse Authors
// This file is part of the mouse library.
//
// The mouse library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The mouse library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the mouse library. If not, see <http://www.gnu.org/licenses/>.

package miner

import (
	"bytes"
	"errors"
	mapset "github.com/deckarep/golang-set"
	"github.com/marcopoloprotoco/mouse/common"
	"github.com/marcopoloprotoco/mouse/common/hexutil"
	"github.com/marcopoloprotoco/mouse/consensus"
	"github.com/marcopoloprotoco/mouse/consensus/misc"
	"github.com/marcopoloprotoco/mouse/core"
	"github.com/marcopoloprotoco/mouse/core/state"
	"github.com/marcopoloprotoco/mouse/core/types"
	"github.com/marcopoloprotoco/mouse/core/ulvp"
	"github.com/marcopoloprotoco/mouse/event"
	"github.com/marcopoloprotoco/mouse/log"
	"github.com/marcopoloprotoco/mouse/params"
	"github.com/marcopoloprotoco/mouse/rlp"
	"github.com/marcopoloprotoco/mouse/trie"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// resultQueueSize is the size of channel listening to sealing result.
	resultQueueSize = 10

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10

	// chainSideChanSize is the size of channel listening to ChainSideEvent.
	chainSideChanSize = 10

	// resubmitAdjustChanSize is the size of resubmitting interval adjustment channel.
	resubmitAdjustChanSize = 10

	// miningLogAtDepth is the number of confirmations before logging successful mining.
	miningLogAtDepth = 7

	// minRecommitInterval is the minimal time interval to recreate the mining block with
	// any newly arrived transactions.
	minRecommitInterval = 1 * time.Second

	// maxRecommitInterval is the maximum time interval to recreate the mining block with
	// any newly arrived transactions.
	maxRecommitInterval = 15 * time.Second

	// intervalAdjustRatio is the impact a single interval adjustment has on sealing work
	// resubmitting interval.
	intervalAdjustRatio = 0.1

	// intervalAdjustBias is applied during the new resubmit interval calculation in favor of
	// increasing upper limit or decreasing lower limit so that the limit can be reachable.
	intervalAdjustBias = 200 * 1000.0 * 1000.0

	// staleThreshold is the maximum depth of the acceptable stale block.
	staleThreshold = 7
)

var (
	emptyHash = [32]byte{}
)

// environment is the worker's current environment and holds all of the current state information.
type environment struct {
	signer types.Signer

	state     *state.StateDB // apply state changes here
	ancestors mapset.Set     // ancestor set (used for checking uncle parent validity)
	family    mapset.Set     // family set (used for checking uncle invalidity)
	uncles    mapset.Set     // uncle set
	tcount    int            // tx count in cycle
	gasPool   *core.GasPool  // available gas used to pack transactions

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt
}

// task contains all information for consensus engine sealing and result submitting.
type task struct {
	receipts  []*types.Receipt
	state     *state.StateDB
	block     *types.Block
	createdAt time.Time
}

const (
	commitInterruptNone int32 = iota
	commitInterruptNewHead
	commitInterruptResubmit
)

// newWorkReq represents a request for new sealing work submitting with relative interrupt notifier.
type newWorkReq struct {
	interrupt *int32
	noempty   bool
	timestamp int64
}

// intervalAdjust represents a resubmitting interval adjustment.
type intervalAdjust struct {
	ratio float64
	inc   bool
}

// worker is the main object which takes care of submitting new work to consensus engine
// and gathering the sealing result.
type worker struct {
	config      *Config
	chainConfig *params.ChainConfig
	engine      consensus.Engine
	mos         Backend
	chain       *core.BlockChain

	// Feeds
	pendingLogsFeed event.Feed

	// Subscriptions
	mux          *event.TypeMux
	txsCh        chan core.NewTxsEvent
	txsSub       event.Subscription
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription
	chainSideCh  chan core.ChainSideEvent
	chainSideSub event.Subscription

	// Channels
	newWorkCh          chan *newWorkReq
	taskCh             chan *task
	resultCh           chan *types.Block
	startCh            chan struct{}
	exitCh             chan struct{}
	resubmitIntervalCh chan time.Duration
	resubmitAdjustCh   chan *intervalAdjust

	current      *environment                 // An environment for current running cycle.
	localUncles  map[common.Hash]*types.Block // A set of side blocks generated locally as the possible uncle blocks.
	remoteUncles map[common.Hash]*types.Block // A set of side blocks as the possible uncle blocks.
	unconfirmed  *unconfirmedBlocks           // A set of locally mined blocks pending canonicalness confirmations.

	mu       sync.RWMutex // The lock used to protect the coinbase and extra fields
	coinbase common.Address
	extra    []byte

	pendingMu    sync.RWMutex
	pendingTasks map[common.Hash]*task

	snapshotMu    sync.RWMutex // The lock used to protect the block snapshot and state snapshot
	snapshotBlock *types.Block
	snapshotState *state.StateDB

	// atomic status counters
	running int32 // The indicator whether the consensus engine is running or not.
	newTxs  int32 // New arrival transaction count since last sealing work submitting.

	// noempty is the flag used to control whether the feature of pre-seal empty
	// block is enabled. The default value is false(pre-seal is enabled by default).
	// But in some special scenario the consensus engine will seal blocks instantaneously,
	// in this case this feature will add all empty blocks into canonical chain
	// non-stop and no real transaction will be included.
	noempty uint32

	cmList    map[common.Hash]*ReqTransaction
	cmListMu  sync.RWMutex
	cmProof   map[common.Hash]*ulvp.SimpleUlvpProof
	cmProofMu sync.RWMutex
	cmAtomic  int32

	// External functions
	isLocalBlock func(block *types.Block) bool // Function used to determine whether the specified block is mined by local miner.

	// Test hooks
	newTaskHook  func(*task)                        // Method to call upon receiving a new sealing task.
	skipSealHook func(*task) bool                   // Method to decide whether skipping the sealing.
	fullTaskHook func()                             // Method to call before pushing the full sealing task.
	resubmitHook func(time.Duration, time.Duration) // Method to call upon updating resubmitting interval.
}

type ReqTransaction struct {
	Tx    *types.Transaction
	Quest bool
}

func newWorker(config *Config, chainConfig *params.ChainConfig, engine consensus.Engine, mos Backend, mux *event.TypeMux, isLocalBlock func(*types.Block) bool, init bool) *worker {
	worker := &worker{
		config:             config,
		chainConfig:        chainConfig,
		engine:             engine,
		mos:                mos,
		mux:                mux,
		chain:              mos.BlockChain(),
		isLocalBlock:       isLocalBlock,
		localUncles:        make(map[common.Hash]*types.Block),
		remoteUncles:       make(map[common.Hash]*types.Block),
		unconfirmed:        newUnconfirmedBlocks(mos.BlockChain(), miningLogAtDepth),
		pendingTasks:       make(map[common.Hash]*task),
		txsCh:              make(chan core.NewTxsEvent, txChanSize),
		chainHeadCh:        make(chan core.ChainHeadEvent, chainHeadChanSize),
		chainSideCh:        make(chan core.ChainSideEvent, chainSideChanSize),
		newWorkCh:          make(chan *newWorkReq),
		taskCh:             make(chan *task),
		resultCh:           make(chan *types.Block, resultQueueSize),
		exitCh:             make(chan struct{}),
		startCh:            make(chan struct{}, 1),
		resubmitIntervalCh: make(chan time.Duration),
		resubmitAdjustCh:   make(chan *intervalAdjust, resubmitAdjustChanSize),
		cmList:             make(map[common.Hash]*ReqTransaction),
		cmProof:            make(map[common.Hash]*ulvp.SimpleUlvpProof),
	}
	// Subscribe NewTxsEvent for tx pool
	worker.txsSub = mos.TxPool().SubscribeNewTxsEvent(worker.txsCh)
	// Subscribe events for blockchain
	worker.chainHeadSub = mos.BlockChain().SubscribeChainHeadEvent(worker.chainHeadCh)
	worker.chainSideSub = mos.BlockChain().SubscribeChainSideEvent(worker.chainSideCh)

	// Sanitize recommit interval if the user-specified one is too short.
	recommit := worker.config.Recommit
	if recommit < minRecommitInterval {
		log.Warn("Sanitizing miner recommit interval", "provided", recommit, "updated", minRecommitInterval)
		recommit = minRecommitInterval
	}

	go worker.mainLoop()
	go worker.newWorkLoop(recommit)
	go worker.resultLoop()
	go worker.taskLoop()

	// Submit first work to initialize pending state.
	if init {
		worker.startCh <- struct{}{}
	}
	return worker
}

// setEtherbase sets the etherbase used to initialize the block coinbase field.
func (w *worker) setEtherbase(addr common.Address) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coinbase = addr
}

// setExtra sets the content used to initialize the block extra field.
func (w *worker) setExtra(extra []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.extra = extra
}

// setRecommitInterval updates the interval for miner sealing work recommitting.
func (w *worker) setRecommitInterval(interval time.Duration) {
	w.resubmitIntervalCh <- interval
}

// disablePreseal disables pre-sealing mining feature
func (w *worker) disablePreseal() {
	atomic.StoreUint32(&w.noempty, 1)
}

// enablePreseal enables pre-sealing mining feature
func (w *worker) enablePreseal() {
	atomic.StoreUint32(&w.noempty, 0)
}

// pending returns the pending state and corresponding block.
func (w *worker) pending() (*types.Block, *state.StateDB) {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	if w.snapshotState == nil {
		return nil, nil
	}
	return w.snapshotBlock, w.snapshotState.Copy()
}

// pendingBlock returns pending block.
func (w *worker) pendingBlock() *types.Block {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock
}

// start sets the running status as 1 and triggers new work submitting.
func (w *worker) start() {
	atomic.StoreInt32(&w.running, 1)
	w.startCh <- struct{}{}
}

// stop sets the running status as 0.
func (w *worker) stop() {
	atomic.StoreInt32(&w.running, 0)
}

// isRunning returns an indicator whether worker is running or not.
func (w *worker) isRunning() bool {
	return atomic.LoadInt32(&w.running) == 1
}

// close terminates all background threads maintained by the worker.
// Note the worker does not support being closed multiple times.
func (w *worker) close() {
	atomic.StoreInt32(&w.running, 0)
	close(w.exitCh)
}

// recalcRecommit recalculates the resubmitting interval upon feedback.
func recalcRecommit(minRecommit, prev time.Duration, target float64, inc bool) time.Duration {
	var (
		prevF = float64(prev.Nanoseconds())
		next  float64
	)
	if inc {
		next = prevF*(1-intervalAdjustRatio) + intervalAdjustRatio*(target+intervalAdjustBias)
		max := float64(maxRecommitInterval.Nanoseconds())
		if next > max {
			next = max
		}
	} else {
		next = prevF*(1-intervalAdjustRatio) + intervalAdjustRatio*(target-intervalAdjustBias)
		min := float64(minRecommit.Nanoseconds())
		if next < min {
			next = min
		}
	}
	return time.Duration(int64(next))
}

// newWorkLoop is a standalone goroutine to submit new mining work upon received events.
func (w *worker) newWorkLoop(recommit time.Duration) {
	var (
		interrupt   *int32
		minRecommit = recommit // minimal resubmit interval specified by user.
		timestamp   int64      // timestamp for each round of mining.
	)

	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C // discard the initial tick

	// commit aborts in-flight transaction execution with given signal and resubmits a new one.
	commit := func(noempty bool, s int32) {
		if interrupt != nil {
			atomic.StoreInt32(interrupt, s)
		}
		interrupt = new(int32)
		w.newWorkCh <- &newWorkReq{interrupt: interrupt, noempty: noempty, timestamp: timestamp}
		timer.Reset(recommit)
		atomic.StoreInt32(&w.newTxs, 0)
	}
	// clearPending cleans the stale pending tasks.
	clearPending := func(number uint64) {
		w.pendingMu.Lock()
		for h, t := range w.pendingTasks {
			if t.block.NumberU64()+staleThreshold <= number {
				delete(w.pendingTasks, h)
			}
		}
		w.pendingMu.Unlock()
	}

	for {
		select {
		case <-w.startCh:
			clearPending(w.chain.CurrentBlock().NumberU64())
			timestamp = time.Now().Unix()
			commit(false, commitInterruptNewHead)

		case head := <-w.chainHeadCh:
			clearPending(head.Block.NumberU64())

			var cTxs []common.Hash
			var txs []*types.Transaction
			for _, tx := range head.Block.Transactions() {
				if txhash := tx.PackCM(); txhash != (common.Hash{}) {
					cTxs = append(cTxs, txhash)
					txs = append(txs, tx)
				}
			}
			if len(cTxs) != 0 {
				w.deleteCM(txs, cTxs, head.Block)
			}

			timestamp = time.Now().Unix()
			commit(false, commitInterruptNewHead)

		case <-timer.C:
			// If mining is running resubmit a new work cycle periodically to pull in
			// higher priced transactions. Disable this overhead for pending blocks.
			if w.isRunning() && (w.chainConfig.Clique == nil || w.chainConfig.Clique.Period > 0) {
				// Short circuit if no new transaction arrives.
				if atomic.LoadInt32(&w.newTxs) == 0 {
					timer.Reset(recommit)
					continue
				}
				commit(true, commitInterruptResubmit)
			}

		case interval := <-w.resubmitIntervalCh:
			// Adjust resubmit interval explicitly by user.
			if interval < minRecommitInterval {
				log.Warn("Sanitizing miner recommit interval", "provided", interval, "updated", minRecommitInterval)
				interval = minRecommitInterval
			}
			log.Info("Miner recommit interval update", "from", minRecommit, "to", interval)
			minRecommit, recommit = interval, interval

			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		case adjust := <-w.resubmitAdjustCh:
			// Adjust resubmit interval by feedback.
			if adjust.inc {
				before := recommit
				target := float64(recommit.Nanoseconds()) / adjust.ratio
				recommit = recalcRecommit(minRecommit, recommit, target, true)
				log.Trace("Increase miner recommit interval", "from", before, "to", recommit)
			} else {
				before := recommit
				recommit = recalcRecommit(minRecommit, recommit, float64(minRecommit.Nanoseconds()), false)
				log.Trace("Decrease miner recommit interval", "from", before, "to", recommit)
			}

			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		case <-w.exitCh:
			return
		}
	}
}

// mainLoop is a standalone goroutine to regenerate the sealing task based on the received event.
func (w *worker) mainLoop() {
	defer w.txsSub.Unsubscribe()
	defer w.chainHeadSub.Unsubscribe()
	defer w.chainSideSub.Unsubscribe()
	events := w.mux.Subscribe(core.NewOtherTxsEvent{}, core.NewProofEvent{})
	defer events.Unsubscribe()

	request := false
	for {
		select {
		case ev := <-events.Chan():
			if ev == nil {
				return
			}
			switch ev.Data.(type) {
			case core.NewOtherTxsEvent:
				if ev, ok := ev.Data.(core.NewOtherTxsEvent); ok {
					for _, tx := range ev.Txs {
						log.Info("Insert xcm transaction", "tx", tx.Hash().Hex())
						if w.insertCM(tx) && !request {
							request = true
							w.requestCrossTxProof(tx.Hash())
						}
					}
				}
			case core.NewProofEvent:
				if ev, ok := ev.Data.(core.NewProofEvent); ok {
					mrProof := ev.MRProof

					if !mrProof.Result {
						log.Info("Receive xcm transaction proof failed", "result", mrProof.Result)
						w.requestCrossTxProof(mrProof.TxHash)
					} else {
						log.Info("Receive xcm transaction proof", "Number", ev.MRProof.Header.Number, "result", ev.MRProof.Result)
						w.insertCMProof(mrProof)

						w.RequestCM(mrProof.TxHash)

						txs := w.cmPendingTx()

						if len(txs) == 0 {
							request = false
						}

						for _, tx := range txs {
							w.requestCrossTxProof(tx.Hash())
							break
						}
					}
				}
			}

		case req := <-w.newWorkCh:
			w.commitNewWork(req.interrupt, req.noempty, req.timestamp)

		case ev := <-w.chainSideCh:
			// Short circuit for duplicate side blocks
			if _, exist := w.localUncles[ev.Block.Hash()]; exist {
				continue
			}
			if _, exist := w.remoteUncles[ev.Block.Hash()]; exist {
				continue
			}
			// Add side block to possible uncle block set depending on the author.
			if w.isLocalBlock != nil && w.isLocalBlock(ev.Block) {
				w.localUncles[ev.Block.Hash()] = ev.Block
			} else {
				w.remoteUncles[ev.Block.Hash()] = ev.Block
			}
			// If our mining block contains less than 2 uncle blocks,
			// add the new uncle block if valid and regenerate a mining block.
			if w.isRunning() && w.current != nil && w.current.uncles.Cardinality() < 2 {
				start := time.Now()
				if err := w.commitUncle(w.current, ev.Block.Header()); err == nil {
					var uncles []*types.Header
					w.current.uncles.Each(func(item interface{}) bool {
						hash, ok := item.(common.Hash)
						if !ok {
							return false
						}
						uncle, exist := w.localUncles[hash]
						if !exist {
							uncle, exist = w.remoteUncles[hash]
						}
						if !exist {
							return false
						}
						uncles = append(uncles, uncle.Header())
						return false
					})
					w.commit(uncles, nil, true, start)
				}
			}

		case ev := <-w.txsCh:
			// Apply transactions to the pending state if we're not mining.
			//
			// Note all transactions received may not be continuous with transactions
			// already included in the current mining block. These transactions will
			// be automatically eliminated.
			if !w.isRunning() && w.current != nil {
				// If block is already full, abort
				if gp := w.current.gasPool; gp != nil && gp.Gas() < params.TxGas {
					continue
				}
				w.mu.RLock()
				coinbase := w.coinbase
				w.mu.RUnlock()

				txs := make(map[common.Address]types.Transactions)
				for _, tx := range ev.Txs {
					acc, _ := types.Sender(w.current.signer, tx)
					txs[acc] = append(txs[acc], tx)
				}
				txset := types.NewTransactionsByPriceAndNonce(w.current.signer, txs)
				tcount := w.current.tcount
				w.commitTransactions(txset, coinbase, nil)
				// Only update the snapshot if any new transactons were added
				// to the pending block
				if tcount != w.current.tcount {
					w.updateSnapshot()
				}
			} else {
				// Special case, if the consensus engine is 0 period clique(dev mode),
				// submit mining work here since all empty submission will be rejected
				// by clique. Of course the advance sealing(empty submission) is disabled.
				if w.chainConfig.Clique != nil && w.chainConfig.Clique.Period == 0 {
					w.commitNewWork(nil, true, time.Now().Unix())
				}
			}
			atomic.AddInt32(&w.newTxs, int32(len(ev.Txs)))

		// System stopped
		case <-w.exitCh:
			return
		case <-w.txsSub.Err():
			return
		case <-w.chainHeadSub.Err():
			return
		case <-w.chainSideSub.Err():
			return
		}
	}
}

// taskLoop is a standalone goroutine to fetch sealing task from the generator and
// push them to consensus engine.
func (w *worker) taskLoop() {
	var (
		stopCh chan struct{}
		prev   common.Hash
	)

	// interrupt aborts the in-flight sealing task.
	interrupt := func() {
		if stopCh != nil {
			close(stopCh)
			stopCh = nil
		}
	}
	for {
		select {
		case task := <-w.taskCh:
			if w.newTaskHook != nil {
				w.newTaskHook(task)
			}
			// Reject duplicate sealing work due to resubmitting.
			sealHash := w.engine.SealHash(task.block.Header())
			if sealHash == prev {
				continue
			}
			// Interrupt previous sealing operation
			interrupt()
			stopCh, prev = make(chan struct{}), sealHash

			if w.skipSealHook != nil && w.skipSealHook(task) {
				continue
			}
			w.pendingMu.Lock()
			w.pendingTasks[sealHash] = task
			w.pendingMu.Unlock()

			if err := w.engine.Seal(w.chain, task.block, w.resultCh, stopCh); err != nil {
				log.Warn("Block sealing failed", "err", err)
			}
		case <-w.exitCh:
			interrupt()
			return
		}
	}
}

// resultLoop is a standalone goroutine to handle sealing result submitting
// and flush relative data to the database.
func (w *worker) resultLoop() {
	for {
		select {
		case block := <-w.resultCh:
			// Short circuit when receiving empty result.
			if block == nil {
				continue
			}
			// Short circuit when receiving duplicate result caused by resubmitting.
			if w.chain.HasBlock(block.Hash(), block.NumberU64()) {
				continue
			}
			var (
				sealhash = w.engine.SealHash(block.Header())
				hash     = block.Hash()
			)
			w.pendingMu.RLock()
			task, exist := w.pendingTasks[sealhash]
			w.pendingMu.RUnlock()
			if !exist {
				log.Error("Block found but no relative pending task", "number", block.Number(), "sealhash", sealhash, "hash", hash)
				continue
			}
			// Different block could share same sealhash, deep copy here to prevent write-write conflict.
			var (
				receipts = make([]*types.Receipt, len(task.receipts))
				logs     []*types.Log
			)
			for i, receipt := range task.receipts {
				// add block location fields
				receipt.BlockHash = hash
				receipt.BlockNumber = block.Number()
				receipt.TransactionIndex = uint(i)

				receipts[i] = new(types.Receipt)
				*receipts[i] = *receipt
				// Update the block hash in all logs since it is now available and not when the
				// receipt/log of individual transactions were created.
				for _, log := range receipt.Logs {
					log.BlockHash = hash
				}
				logs = append(logs, receipt.Logs...)
			}
			// Commit block and state to database.
			_, err := w.chain.WriteBlockWithState(block, receipts, logs, task.state, true)
			if err != nil {
				log.Error("Failed writing block to chain", "err", err)
				continue
			}
			err = w.chain.PushBlockInMMR(block, true)
			if err != nil {
				log.Warn("PushBlockInMMR failed", "number", block.Number(), "err", err)
			} else {
				log.Info("Successfully sealed new block", "number", block.Number(), "sealhash", sealhash, "hash", hash,
					"elapsed", common.PrettyDuration(time.Since(task.createdAt)))
			}

			// Broadcast the block and announce chain insertion event
			w.mux.Post(core.NewMinedBlockEvent{Block: block})

			// Insert the block into the set of pending ones to resultLoop for confirmations
			w.unconfirmed.Insert(block.NumberU64(), block.Hash())

		case <-w.exitCh:
			return
		}
	}
}

// makeCurrent creates a new environment for the current cycle.
func (w *worker) makeCurrent(parent *types.Block, header *types.Header) error {
	state, err := w.chain.StateAt(parent.Root())
	if err != nil {
		return err
	}
	env := &environment{
		signer:    types.NewEIP155Signer(w.chainConfig.ChainID),
		state:     state,
		ancestors: mapset.NewSet(),
		family:    mapset.NewSet(),
		uncles:    mapset.NewSet(),
		header:    header,
	}

	// when 08 is processed ancestors contain 07 (quick block)
	for _, ancestor := range w.chain.GetBlocksFromHash(parent.Hash(), 7) {
		for _, uncle := range ancestor.Uncles() {
			env.family.Add(uncle.Hash())
		}
		env.family.Add(ancestor.Hash())
		env.ancestors.Add(ancestor.Hash())
	}

	// Keep track of transactions which return errors so they can be removed
	env.tcount = 0
	w.current = env
	return nil
}

// commitUncle adds the given block to uncle block set, returns error if failed to add.
func (w *worker) commitUncle(env *environment, uncle *types.Header) error {
	hash := uncle.Hash()
	if env.uncles.Contains(hash) {
		return errors.New("uncle not unique")
	}
	if env.header.ParentHash == uncle.ParentHash {
		return errors.New("uncle is sibling")
	}
	if !env.ancestors.Contains(uncle.ParentHash) {
		return errors.New("uncle's parent unknown")
	}
	if env.family.Contains(hash) {
		return errors.New("uncle already included")
	}
	env.uncles.Add(uncle.Hash())
	return nil
}

// updateSnapshot updates pending snapshot block and state.
// Note this function assumes the current variable is thread safe.
func (w *worker) updateSnapshot() {
	w.snapshotMu.Lock()
	defer w.snapshotMu.Unlock()

	var uncles []*types.Header
	w.current.uncles.Each(func(item interface{}) bool {
		hash, ok := item.(common.Hash)
		if !ok {
			return false
		}
		uncle, exist := w.localUncles[hash]
		if !exist {
			uncle, exist = w.remoteUncles[hash]
		}
		if !exist {
			return false
		}
		uncles = append(uncles, uncle.Header())
		return false
	})

	w.snapshotBlock = types.NewBlock(
		w.current.header,
		w.current.txs,
		uncles,
		w.current.receipts,
		new(trie.Trie),
	)

	w.snapshotState = w.current.state.Copy()
}

func (w *worker) commitTransaction(tx *types.Transaction, coinbase common.Address) ([]*types.Log, error) {
	snap := w.current.state.Snapshot()

	receipt, err := core.ApplyTransaction(w.chainConfig, w.chain, &coinbase, w.current.gasPool, w.current.state, w.current.header, tx, &w.current.header.GasUsed, *w.chain.GetVMConfig())
	if err != nil {
		w.current.state.RevertToSnapshot(snap)
		return nil, err
	}
	w.current.txs = append(w.current.txs, tx)
	w.current.receipts = append(w.current.receipts, receipt)

	return receipt.Logs, nil
}

func (w *worker) commitCMTransactions(txs []*ulvp.UlvpTransaction, coinbase common.Address, interrupt *int32) bool {
	if w.current == nil {
		return true
	}

	if w.current.gasPool == nil {
		w.current.gasPool = new(core.GasPool).AddGas(w.current.header.GasLimit)
	}

	var coalescedLogs []*types.Log

	for _, cm := range txs {
		// In the following three cases, we will interrupt the execution of the transaction.
		// (1) new head block event arrival, the interrupt signal is 1
		// (2) worker start or restart, the interrupt signal is 1
		// (3) worker recreate the mining block with any newly arrived transactions, the interrupt signal is 2.
		// For the first two cases, the semi-finished work will be discarded.
		// For the third case, the semi-finished work will be submitted to the consensus engine.
		tx := makeCMTransaction(cm, w.current.state.GetNonce(types.SysSender))
		if interrupt != nil && atomic.LoadInt32(interrupt) != commitInterruptNone {
			// Notify resubmit loop to increase resubmitting interval due to too frequent commits.
			if atomic.LoadInt32(interrupt) == commitInterruptResubmit {
				ratio := float64(w.current.header.GasLimit-w.current.gasPool.Gas()) / float64(w.current.header.GasLimit)
				if ratio < 0.1 {
					ratio = 0.1
				}
				w.resubmitAdjustCh <- &intervalAdjust{
					ratio: ratio,
					inc:   true,
				}
			}
			return atomic.LoadInt32(interrupt) == commitInterruptNewHead
		}

		// Start executing the transaction
		w.current.state.Prepare(tx.Hash(), common.Hash{}, w.current.tcount)

		log.Warn("CM prepare transaction", "hash", tx.Hash().Hex())
		logs, err := w.commitTransaction(tx, coinbase)
		switch err {
		case nil:
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			w.current.tcount++

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
		}
	}

	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are mining. The reason is that
		// when we are mining, the worker will regenerate a mining block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.

		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		w.pendingLogsFeed.Send(cpy)
	}
	// Notify resubmit loop to decrease resubmitting interval if current interval is larger
	// than the user-specified one.
	if interrupt != nil {
		w.resubmitAdjustCh <- &intervalAdjust{inc: false}
	}

	return false
}

func (w *worker) commitTransactions(txs *types.TransactionsByPriceAndNonce, coinbase common.Address, interrupt *int32) bool {
	// Short circuit if current is nil
	if w.current == nil {
		return true
	}

	if w.current.gasPool == nil {
		w.current.gasPool = new(core.GasPool).AddGas(w.current.header.GasLimit)
	}

	var coalescedLogs []*types.Log

	for {
		// In the following three cases, we will interrupt the execution of the transaction.
		// (1) new head block event arrival, the interrupt signal is 1
		// (2) worker start or restart, the interrupt signal is 1
		// (3) worker recreate the mining block with any newly arrived transactions, the interrupt signal is 2.
		// For the first two cases, the semi-finished work will be discarded.
		// For the third case, the semi-finished work will be submitted to the consensus engine.
		if interrupt != nil && atomic.LoadInt32(interrupt) != commitInterruptNone {
			// Notify resubmit loop to increase resubmitting interval due to too frequent commits.
			if atomic.LoadInt32(interrupt) == commitInterruptResubmit {
				ratio := float64(w.current.header.GasLimit-w.current.gasPool.Gas()) / float64(w.current.header.GasLimit)
				if ratio < 0.1 {
					ratio = 0.1
				}
				w.resubmitAdjustCh <- &intervalAdjust{
					ratio: ratio,
					inc:   true,
				}
			}
			return atomic.LoadInt32(interrupt) == commitInterruptNewHead
		}
		// If we don't have enough gas for any further transactions then we're done
		if w.current.gasPool.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "have", w.current.gasPool, "want", params.TxGas)
			break
		}
		// Retrieve the next transaction and abort if all done
		tx := txs.Peek()
		if tx == nil {
			break
		}
		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		//
		// We use the eip155 signer regardless of the current hf.
		from, _ := types.Sender(w.current.signer, tx)
		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !w.chainConfig.IsEIP155(w.current.header.Number) {
			log.Trace("Ignoring reply protected transaction", "hash", tx.Hash(), "eip155", w.chainConfig.EIP155Block)

			txs.Pop()
			continue
		}
		// Start executing the transaction
		w.current.state.Prepare(tx.Hash(), common.Hash{}, w.current.tcount)

		logs, err := w.commitTransaction(tx, coinbase)
		switch err {
		case core.ErrGasLimitReached:
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Trace("Gas limit exceeded for current block", "sender", from)
			txs.Pop()

		case core.ErrNonceTooLow:
			// New head notification data race between the transaction pool and miner, shift
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			txs.Shift()

		case core.ErrNonceTooHigh:
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			txs.Pop()

		case nil:
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			w.current.tcount++
			txs.Shift()

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Shift()
		}
	}

	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are mining. The reason is that
		// when we are mining, the worker will regenerate a mining block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.

		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		w.pendingLogsFeed.Send(cpy)
	}
	// Notify resubmit loop to decrease resubmitting interval if current interval is larger
	// than the user-specified one.
	if interrupt != nil {
		w.resubmitAdjustCh <- &intervalAdjust{inc: false}
	}
	return false
}

// commitNewWork generates several new sealing tasks based on the parent block.
func (w *worker) commitNewWork(interrupt *int32, noempty bool, timestamp int64) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	tstart := time.Now()
	parent := w.chain.CurrentBlock()

	if parent.Time() >= uint64(timestamp) {
		timestamp = int64(parent.Time() + 1)
	}
	// this will ensure we're not going off too far in the future
	if now := time.Now().Unix(); timestamp > now+1 {
		wait := time.Duration(timestamp-now) * time.Second
		log.Info("Mining too far in the future", "wait", common.PrettyDuration(wait))
		time.Sleep(wait)
	}
	num, preRoot := parent.Number(), parent.MmrRoot()
	root := w.chain.GetMmrRoot()

	if !bytes.Equal(emptyHash[:], root[:]) && bytes.Equal(preRoot[:], root[:]) {
		time.Sleep(2000 * time.Millisecond)

		for {
			root = w.chain.GetMmrRoot()
			if !bytes.Equal(preRoot[:], root[:]) {
				break
			}
			time.Sleep(2000 * time.Millisecond)
		}
	}

	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     num.Add(num, common.Big1),
		GasLimit:   core.CalcGasLimit(parent, w.config.GasFloor, w.config.GasCeil),
		Extra:      w.extra,
		Time:       uint64(timestamp),
		MmrRoot:    root,
	}
	// if header.Number.Cmp(common.Big1) == 0 {
	// 	testTx := types.NewTransaction(0, types.GenToken, nil, 0, nil, nil)
	// 	w.cmList[testTx.Hash()] = testTx
	// }

	// Only set the coinbase if our consensus engine is running (avoid spurious block rewards)
	if w.isRunning() {
		if w.coinbase == (common.Address{}) {
			log.Error("Refusing to mine without etherbase")
			return
		}
		header.Coinbase = w.coinbase
	}
	if err := w.engine.Prepare(w.chain, header); err != nil {
		log.Error("Failed to prepare header for mining", "err", err)
		return
	}
	// If we are care about TheDAO hard-fork check whether to override the extra-data or not
	if daoBlock := w.chainConfig.DAOForkBlock; daoBlock != nil {
		// Check whether the block is among the fork extra-override range
		limit := new(big.Int).Add(daoBlock, params.DAOForkExtraRange)
		if header.Number.Cmp(daoBlock) >= 0 && header.Number.Cmp(limit) < 0 {
			// Depending whether we support or oppose the fork, override differently
			if w.chainConfig.DAOForkSupport {
				header.Extra = common.CopyBytes(params.DAOForkBlockExtra)
			} else if bytes.Equal(header.Extra, params.DAOForkBlockExtra) {
				header.Extra = []byte{} // If miner opposes, don't let it use the reserved extra-data
			}
		}
	}
	// Could potentially happen if starting to mine in an odd state.
	err := w.makeCurrent(parent, header)
	if err != nil {
		log.Error("Failed to create mining context", "err", err)
		return
	}
	// Create the current work task and check any fork transitions needed
	env := w.current
	if w.chainConfig.DAOForkSupport && w.chainConfig.DAOForkBlock != nil && w.chainConfig.DAOForkBlock.Cmp(header.Number) == 0 {
		misc.ApplyDAOHardFork(env.state)
	}
	// Accumulate the uncles for the current block
	uncles := make([]*types.Header, 0, 2)
	commitUncles := func(blocks map[common.Hash]*types.Block) {
		// Clean up stale uncle blocks first
		for hash, uncle := range blocks {
			if uncle.NumberU64()+staleThreshold <= header.Number.Uint64() {
				delete(blocks, hash)
			}
		}
		for hash, uncle := range blocks {
			if len(uncles) == 2 {
				break
			}
			if err := w.commitUncle(env, uncle.Header()); err != nil {
				log.Trace("Possible uncle rejected", "hash", hash, "reason", err)
			} else {
				log.Debug("Committing new uncle to block", "hash", hash)
				uncles = append(uncles, uncle.Header())
			}
		}
	}
	// Prefer to locally generated uncle
	commitUncles(w.localUncles)
	commitUncles(w.remoteUncles)

	// Create an empty block based on temporary copied state for
	// sealing in advance without waiting block execution finished.
	// if !noempty && atomic.LoadUint32(&w.noempty) == 0 {
	// 	w.commit(uncles, nil, false, tstart)
	// }

	// Fill the block with all available pending transactions.
	pending, err := w.mos.TxPool().Pending()
	if err != nil {
		log.Error("Failed to fetch pending transactions", "err", err)
		return
	}
	// Short circuit if there is no available pending transactions.
	// But if we disable empty precommit already, ignore it. Since
	// empty block is necessary to keep the liveness of the network.
	// if len(pending) == 0 && atomic.LoadUint32(&w.noempty) == 0 {
	// 	w.updateSnapshot()
	// 	return
	// }
	// Split the pending transactions into locals and remotes
	localTxs, remoteTxs := make(map[common.Address]types.Transactions), pending
	for _, account := range w.mos.TxPool().Locals() {
		if txs := remoteTxs[account]; len(txs) > 0 {
			delete(remoteTxs, account)
			localTxs[account] = txs
		}
	}
	if len(localTxs) > 0 {
		txs := types.NewTransactionsByPriceAndNonce(w.current.signer, localTxs)
		if w.commitTransactions(txs, w.coinbase, interrupt) {
			return
		}
	}

	if header.Number.Cmp(common.Big1) == 0 {
		txs := types.NewTransactionsByPriceAndNonce(w.current.signer, map[common.Address]types.Transactions{
			common.HexToAddress("0x81220F9CDf63c04F877f620328A4873F1Cc09038"): w.builtinTx()})
		if w.commitTransactions(txs, w.coinbase, interrupt) {
			log.Error("Failed to fetch builtin transactions", "err", err)
			return
		}
		log.Info("Commit builtin transactions")
	}

	if len(remoteTxs) > 0 {
		txs := types.NewTransactionsByPriceAndNonce(w.current.signer, remoteTxs)
		if w.commitTransactions(txs, w.coinbase, interrupt) {
			return
		}
	}

	// Apply CM Transactions
	messages := w.cmPending()
	if w.commitCMTransactions(messages, w.coinbase, interrupt) {
		log.Warn("Commit CM Transaction error")
		return
	}

	w.commit(uncles, w.fullTaskHook, true, tstart)
}

func (w *worker) cmPending() []*ulvp.UlvpTransaction {
	w.cmListMu.RLock()
	defer w.cmListMu.RUnlock()

	pendingProof := w.cmProofPending()
	// Apply CM Transactions
	messages := []*ulvp.UlvpTransaction{}
	for _, tx := range w.cmList {
		if v, ok := pendingProof[tx.Tx.Hash()]; ok {
			tx.Quest = true
			messages = append(messages, &ulvp.UlvpTransaction{SimpUlvpP: v, Tx: tx.Tx})
		}
	}

	return messages
}

func (w *worker) cmPendingTx() types.Transactions {
	w.cmListMu.RLock()
	defer w.cmListMu.RUnlock()

	messages := []*types.Transaction{}
	for _, tx := range w.cmList {
		if !tx.Quest {
			messages = append(messages, tx.Tx)
		}
	}

	return messages
}

func (w *worker) insertCM(tx *types.Transaction) bool {
	w.cmListMu.RLock()
	defer w.cmListMu.RUnlock()
	if _, ok := w.cmList[tx.Hash()]; !ok {
		w.cmList[tx.Hash()] = &ReqTransaction{Tx: tx, Quest: false}
		return true
	}
	return false
}

func (w *worker) deleteCM(txs []*types.Transaction, ctxs []common.Hash, block *types.Block) {
	w.cmListMu.RLock()
	defer w.cmListMu.RUnlock()

	log.Info("deleteCM", "number", block.Number(), "txs", len(ctxs), "hash", ctxs[0].String())

	for i, tx := range ctxs {
		w.mux.Post(core.NewCrossTxEvent{Hash: tx, Tx: txs[i]})
		delete(w.cmList, tx)
		w.deleteCMProof(tx)
	}
}

func (w *worker) RequestCM(txHash common.Hash) {
	w.cmListMu.RLock()
	defer w.cmListMu.RUnlock()
	if v, ok := w.cmList[txHash]; ok {
		v.Quest = true
	}
}

func (w *worker) insertCMProof(mrProof *ulvp.SimpleUlvpProof) {
	w.cmProofMu.RLock()
	defer w.cmProofMu.RUnlock()

	w.cmProof[mrProof.TxHash] = mrProof
}

func (w *worker) deleteCMProof(txHash common.Hash) {
	w.cmProofMu.RLock()
	defer w.cmProofMu.RUnlock()

	delete(w.cmProof, txHash)
}

func (w *worker) cmProofPending() map[common.Hash]*ulvp.SimpleUlvpProof {
	w.cmProofMu.RLock()
	defer w.cmProofMu.RUnlock()

	// Apply CM Transactions
	messages := make(map[common.Hash]*ulvp.SimpleUlvpProof, len(w.cmProof))
	for k, tx := range w.cmProof {
		messages[k] = tx
	}

	return messages
}

// commit runs any post-transaction state modifications, assembles the final block
// and commits new work if consensus engine is running.
func (w *worker) commit(uncles []*types.Header, interval func(), update bool, start time.Time) error {
	// Deep copy receipts here to avoid interaction between different tasks.
	receipts := copyReceipts(w.current.receipts)
	s := w.current.state.Copy()
	block, err := w.engine.FinalizeAndAssemble(w.chain, w.current.header, s, w.current.txs, uncles, receipts)
	if err != nil {
		return err
	}
	if w.isRunning() {
		if interval != nil {
			interval()
		}
		select {
		case w.taskCh <- &task{receipts: receipts, state: s, block: block, createdAt: time.Now()}:
			w.unconfirmed.Shift(block.NumberU64() - 1)
			log.Info("Commit new mining work", "number", block.Number(), "sealhash", w.engine.SealHash(block.Header()),
				"uncles", len(uncles), "txs", w.current.tcount,
				"gas", block.GasUsed(), "fees", totalFees(block, receipts),
				"elapsed", common.PrettyDuration(time.Since(start)))

		case <-w.exitCh:
			log.Info("Worker has exited")
		}
	}
	if update {
		w.updateSnapshot()
	}
	return nil
}
func (w *worker) builtinTx() []*types.Transaction {
	if w.chainConfig.ChainID.Cmp(params.MouseChainConfig.ChainID) == 0 {
		return w.builtinTxA()
	} else if w.chainConfig.ChainID.Cmp(params.DuckChainConfig.ChainID) == 0 {
		return w.builtinTxB()
	}
	return nil
}

func (w *worker) builtinTxA() (txs []*types.Transaction) {
	log.Info("Commit builtinTxA")
	token := types.NewContractCreation(
		0,
		big.NewInt(0),
		1641922,
		big.NewInt(1000000000),
		common.FromHex("60806040523480156200001157600080fd5b5060405162001e2e38038062001e2e833981810160405260208110156200003757600080fd5b81019080805160405193929190846401000000008211156200005857600080fd5b838201915060208201858111156200006f57600080fd5b82518660018202830111640100000000821117156200008d57600080fd5b8083526020830192505050908051906020019080838360005b83811015620000c3578082015181840152602081019050620000a6565b50505050905090810190601f168015620000f15780820380516001836020036101000a031916815260200191505b5060405250505080818160039080519060200190620001129291906200020a565b5080600490805190602001906200012b9291906200020a565b506012600560006101000a81548160ff021916908360ff160217905550505060006200015c6200020260201b60201c565b905080600560016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508073ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050620002b9565b600033905090565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106200024d57805160ff19168380011785556200027e565b828001600101855582156200027e579182015b828111156200027d57825182559160200191906001019062000260565b5b5090506200028d919062000291565b5090565b620002b691905b80821115620002b257600081600090555060010162000298565b5090565b90565b611b6580620002c96000396000f3fe608060405234801561001057600080fd5b50600436106101005760003560e01c8063715018a611610097578063a457c2d711610066578063a457c2d7146104e7578063a9059cbb1461054d578063dd62ed3e146105b3578063f2fde38b1461062b57610100565b8063715018a6146103c25780638da5cb5b146103cc57806395d89b41146104165780639dc29fac1461049957610100565b8063313ce567116100d3578063313ce5671461029257806339509351146102b657806340c10f191461031c57806370a082311461036a57610100565b806306fdde0314610105578063095ea7b31461018857806318160ddd146101ee57806323b872dd1461020c575b600080fd5b61010d61066f565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561014d578082015181840152602081019050610132565b50505050905090810190601f16801561017a5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6101d46004803603604081101561019e57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610711565b604051808215151515815260200191505060405180910390f35b6101f661072f565b6040518082815260200191505060405180910390f35b6102786004803603606081101561022257600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610739565b604051808215151515815260200191505060405180910390f35b61029a610812565b604051808260ff1660ff16815260200191505060405180910390f35b610302600480360360408110156102cc57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610829565b604051808215151515815260200191505060405180910390f35b6103686004803603604081101561033257600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506108dc565b005b6103ac6004803603602081101561038057600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109b4565b6040518082815260200191505060405180910390f35b6103ca6109fc565b005b6103d4610b87565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b61041e610bb1565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561045e578082015181840152602081019050610443565b50505050905090810190601f16801561048b5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6104e5600480360360408110156104af57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610c53565b005b610533600480360360408110156104fd57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610c61565b604051808215151515815260200191505060405180910390f35b6105996004803603604081101561056357600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610d2e565b604051808215151515815260200191505060405180910390f35b610615600480360360408110156105c957600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610d4c565b6040518082815260200191505060405180910390f35b61066d6004803603602081101561064157600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610dd3565b005b606060038054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156107075780601f106106dc57610100808354040283529160200191610707565b820191906000526020600020905b8154815290600101906020018083116106ea57829003601f168201915b5050505050905090565b600061072561071e610fe3565b8484610feb565b6001905092915050565b6000600254905090565b60006107468484846111e2565b61080784610752610fe3565b61080285604051806060016040528060288152602001611a7960289139600160008b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006107b8610fe3565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546114a39092919063ffffffff16565b610feb565b600190509392505050565b6000600560009054906101000a900460ff16905090565b60006108d2610836610fe3565b846108cd8560016000610847610fe3565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461156390919063ffffffff16565b610feb565b6001905092915050565b6108e4610fe3565b73ffffffffffffffffffffffffffffffffffffffff16600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146109a6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b6109b082826115eb565b5050565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b610a04610fe3565b73ffffffffffffffffffffffffffffffffffffffff16600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614610ac6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff16600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a36000600560016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b606060048054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610c495780601f10610c1e57610100808354040283529160200191610c49565b820191906000526020600020905b815481529060010190602001808311610c2c57829003601f168201915b5050505050905090565b610c5d82826117b2565b5050565b6000610d24610c6e610fe3565b84610d1f85604051806060016040528060258152602001611b0b6025913960016000610c98610fe3565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546114a39092919063ffffffff16565b610feb565b6001905092915050565b6000610d42610d3b610fe3565b84846111e2565b6001905092915050565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b610ddb610fe3565b73ffffffffffffffffffffffffffffffffffffffff16600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614610e9d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161415610f23576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526026815260200180611a0b6026913960400191505060405180910390fd5b8073ffffffffffffffffffffffffffffffffffffffff16600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a380600560016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b600033905090565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415611071576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526024815260200180611ae76024913960400191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156110f7576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526022815260200180611a316022913960400191505060405180910390fd5b80600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925836040518082815260200191505060405180910390a3505050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415611268576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526025815260200180611ac26025913960400191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156112ee576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260238152602001806119c66023913960400191505060405180910390fd5b6112f9838383611976565b61136481604051806060016040528060268152602001611a53602691396000808773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546114a39092919063ffffffff16565b6000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506113f7816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461156390919063ffffffff16565b6000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a3505050565b6000838311158290611550576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b838110156115155780820151818401526020810190506114fa565b50505050905090810190601f1680156115425780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b5060008385039050809150509392505050565b6000808284019050838110156115e1576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601b8152602001807f536166654d6174683a206164646974696f6e206f766572666c6f77000000000081525060200191505060405180910390fd5b8091505092915050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16141561168e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601f8152602001807f45524332303a206d696e7420746f20746865207a65726f20616464726573730081525060200191505060405180910390fd5b61169a60008383611976565b6116af8160025461156390919063ffffffff16565b600281905550611706816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461156390919063ffffffff16565b6000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a35050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415611838576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526021815260200180611aa16021913960400191505060405180910390fd5b61184482600083611976565b6118af816040518060600160405280602281526020016119e9602291396000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546114a39092919063ffffffff16565b6000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506119068160025461197b90919063ffffffff16565b600281905550600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a35050565b505050565b60006119bd83836040518060400160405280601e81526020017f536166654d6174683a207375627472616374696f6e206f766572666c6f7700008152506114a3565b90509291505056fe45524332303a207472616e7366657220746f20746865207a65726f206164647265737345524332303a206275726e20616d6f756e7420657863656564732062616c616e63654f776e61626c653a206e6577206f776e657220697320746865207a65726f206164647265737345524332303a20617070726f766520746f20746865207a65726f206164647265737345524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e636545524332303a207472616e7366657220616d6f756e74206578636565647320616c6c6f77616e636545524332303a206275726e2066726f6d20746865207a65726f206164647265737345524332303a207472616e736665722066726f6d20746865207a65726f206164647265737345524332303a20617070726f76652066726f6d20746865207a65726f206164647265737345524332303a2064656372656173656420616c6c6f77616e63652062656c6f77207a65726fa2646970667358221220f1ab638abebc83764e12479badf1f3b68bd67ce3eb7e4ad908b3919259d1917c64736f6c63430006060033000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000056d6f757365000000000000000000000000000000000000000000000000000000"),
	).WithRawSignature(
		big.NewInt(2035),
		hexutil.MustDecodeBig("0xcd27442a4c4f0d134508e02be5a7bc57428ee46f0cf3c62fe33d98327fee5154"),
		hexutil.MustDecodeBig("0x5e1c109592b13781c91d22fbf2394f337b810a60333cc1307fa6cb02cf429219"),
	)

	// ref := types.NewContractCreation(
	// 	1,
	// 	big.NewInt(0),
	// 	644546,
	// 	big.NewInt(1000000000),
	// 	common.FromHex("0x608060405234801561001057600080fd5b50604051610ae3380380610ae38339818101604052602081101561003357600080fd5b8101908080519060200190929190505050806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050610a4f806100946000396000f3fe6080604052600436106100555760003560e01c806348c894911461005a5780635a281296146101225780639485d2931461018757806398791f72146101de578063f3fef3a3146102a6578063f435f5a714610301575b600080fd5b34801561006657600080fd5b506101206004803603602081101561007d57600080fd5b810190808035906020019064010000000081111561009a57600080fd5b8201836020820111156100ac57600080fd5b803590602001918460018302840111640100000000831117156100ce57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610345565b005b34801561012e57600080fd5b506101716004803603602081101561014557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610517565b6040518082815260200191505060405180910390f35b34801561019357600080fd5b5061019c61052f565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b3480156101ea57600080fd5b506102a46004803603602081101561020157600080fd5b810190808035906020019064010000000081111561021e57600080fd5b82018360208201111561023057600080fd5b8035906020019184600183028401116401000000008311171561025257600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610554565b005b3480156102b257600080fd5b506102ff600480360360408110156102c957600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610723565b005b6103436004803603602081101561031757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610835565b005b60008060008060608580602001905160a081101561036257600080fd5b8101908080519060200190929190805190602001909291908051906020019092919080519060200190929190805160405193929190846401000000008211156103aa57600080fd5b838201915060208201858111156103c057600080fd5b82518660018202830111640100000000821117156103dd57600080fd5b8083526020830192505050908051906020019080838360005b838110156104115780820151818401526020810190506103f6565b50505050905090810190601f16801561043e5780820380516001836020036101000a031916815260200191505b50604052505050945094509450945094506000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166340c10f1985856040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050600060405180830381600087803b1580156104f757600080fd5b505af115801561050b573d6000803e3d6000fd5b50505050505050505050565b60016020528060005260406000206000915090505481565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008060008060608580602001905160a081101561057157600080fd5b8101908080519060200190929190805190602001909291908051906020019092919080519060200190929190805160405193929190846401000000008211156105b957600080fd5b838201915060208201858111156105cf57600080fd5b82518660018202830111640100000000821117156105ec57600080fd5b8083526020830192505050908051906020019080838360005b83811015610620578082015181840152602081019050610605565b50505050905090810190601f16801561064d5780820380516001836020036101000a031916815260200191505b5060405250505094509450945094509450478311156106d4576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601d8152602001807f496e73756666696369656e742062616c616e636520776974686472617700000081525060200191505060405180910390fd5b8373ffffffffffffffffffffffffffffffffffffffff166108fc849081150290604051600060405180830381858888f1935050505015801561071a573d6000803e3d6000fd5b50505050505050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16639dc29fac33836040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050600060405180830381600087803b1580156107cb57600080fd5b505af11580156107df573d6000803e3d6000fd5b505050503373ffffffffffffffffffffffffffffffffffffffff167f992ee874049a42cae0757a765cd7f641b6028cc35c3478bde8330bf417c3a7a9826040518082815260200191505060405180910390a25050565b600034116108ab576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600d8152602001807f4c6f636b207a65726f206d61700000000000000000000000000000000000000081525060200191505060405180910390fd5b6108fd34600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461099190919063ffffffff16565b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055503373ffffffffffffffffffffffffffffffffffffffff167f9fe029c6176f2b9fe1394354b760728bc1b5fcc32f2e5f21f981fb7a65102ed6346040518082815260200191505060405180910390a250565b600080828401905083811015610a0f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601b8152602001807f536166654d6174683a206164646974696f6e206f766572666c6f77000000000081525060200191505060405180910390fd5b809150509291505056fea2646970667358221220718f21aa628ec657911ad74a98800cadb0510834958487054c295ec2205074e664736f6c6343000606003300000000000000000000000040fb23023b8bb73a19e949fa00ef3ccf7ee07bb6"),
	// ).WithRawSignature(
	// 	big.NewInt(2035),
	// 	hexutil.MustDecodeBig("0xeb1418299ef79258f43c31011a214249bc02a1cf5b95b27f14eb9a12b6db64b"),
	// 	hexutil.MustDecodeBig("0x6e72a8ab0fa41cf65783b70c0ae51ee824bd1e450386725fc143cb8bf53424ee"),
	// )

	// ch := types.NewTransaction(
	// 	2,
	// 	common.HexToAddress("0x40FB23023B8Bb73a19e949FA00ef3CCF7EE07Bb6"),
	// 	big.NewInt(0),
	// 	31095,
	// 	big.NewInt(1000000000),
	// 	common.FromHex("f2fde38b0000000000000000000000005221538292372ca706a62eb0d4890d2c85543be9"),
	// ).WithRawSignature(
	// 	big.NewInt(2035),
	// 	hexutil.MustDecodeBig("0x6a78a08d301d8d30a46f6cc98a7da3d8fd73b40e7fa50dbbb5571c803dcca2d3"),
	// 	hexutil.MustDecodeBig("0x4e2a0356f4d219110a85b4fd8172ffcbddd1f9032c765dc295b26254604bb377"),
	// )
	// txs = append(txs, token, ref, ch)
	txs = append(txs, token)

	return txs
}

func (w *worker) builtinTxB() (txs []*types.Transaction) {
	log.Info("Commit builtinTxB")
	token := types.NewContractCreation(
		0,
		big.NewInt(0),
		1641910,
		big.NewInt(1000000000),
		common.FromHex("60806040523480156200001157600080fd5b5060405162001e2e38038062001e2e833981810160405260208110156200003757600080fd5b81019080805160405193929190846401000000008211156200005857600080fd5b838201915060208201858111156200006f57600080fd5b82518660018202830111640100000000821117156200008d57600080fd5b8083526020830192505050908051906020019080838360005b83811015620000c3578082015181840152602081019050620000a6565b50505050905090810190601f168015620000f15780820380516001836020036101000a031916815260200191505b5060405250505080818160039080519060200190620001129291906200020a565b5080600490805190602001906200012b9291906200020a565b506012600560006101000a81548160ff021916908360ff160217905550505060006200015c6200020260201b60201c565b905080600560016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508073ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050620002b9565b600033905090565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106200024d57805160ff19168380011785556200027e565b828001600101855582156200027e579182015b828111156200027d57825182559160200191906001019062000260565b5b5090506200028d919062000291565b5090565b620002b691905b80821115620002b257600081600090555060010162000298565b5090565b90565b611b6580620002c96000396000f3fe608060405234801561001057600080fd5b50600436106101005760003560e01c8063715018a611610097578063a457c2d711610066578063a457c2d7146104e7578063a9059cbb1461054d578063dd62ed3e146105b3578063f2fde38b1461062b57610100565b8063715018a6146103c25780638da5cb5b146103cc57806395d89b41146104165780639dc29fac1461049957610100565b8063313ce567116100d3578063313ce5671461029257806339509351146102b657806340c10f191461031c57806370a082311461036a57610100565b806306fdde0314610105578063095ea7b31461018857806318160ddd146101ee57806323b872dd1461020c575b600080fd5b61010d61066f565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561014d578082015181840152602081019050610132565b50505050905090810190601f16801561017a5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6101d46004803603604081101561019e57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610711565b604051808215151515815260200191505060405180910390f35b6101f661072f565b6040518082815260200191505060405180910390f35b6102786004803603606081101561022257600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610739565b604051808215151515815260200191505060405180910390f35b61029a610812565b604051808260ff1660ff16815260200191505060405180910390f35b610302600480360360408110156102cc57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610829565b604051808215151515815260200191505060405180910390f35b6103686004803603604081101561033257600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506108dc565b005b6103ac6004803603602081101561038057600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109b4565b6040518082815260200191505060405180910390f35b6103ca6109fc565b005b6103d4610b87565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b61041e610bb1565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561045e578082015181840152602081019050610443565b50505050905090810190601f16801561048b5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6104e5600480360360408110156104af57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610c53565b005b610533600480360360408110156104fd57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610c61565b604051808215151515815260200191505060405180910390f35b6105996004803603604081101561056357600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610d2e565b604051808215151515815260200191505060405180910390f35b610615600480360360408110156105c957600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610d4c565b6040518082815260200191505060405180910390f35b61066d6004803603602081101561064157600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610dd3565b005b606060038054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156107075780601f106106dc57610100808354040283529160200191610707565b820191906000526020600020905b8154815290600101906020018083116106ea57829003601f168201915b5050505050905090565b600061072561071e610fe3565b8484610feb565b6001905092915050565b6000600254905090565b60006107468484846111e2565b61080784610752610fe3565b61080285604051806060016040528060288152602001611a7960289139600160008b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006107b8610fe3565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546114a39092919063ffffffff16565b610feb565b600190509392505050565b6000600560009054906101000a900460ff16905090565b60006108d2610836610fe3565b846108cd8560016000610847610fe3565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461156390919063ffffffff16565b610feb565b6001905092915050565b6108e4610fe3565b73ffffffffffffffffffffffffffffffffffffffff16600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146109a6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b6109b082826115eb565b5050565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b610a04610fe3565b73ffffffffffffffffffffffffffffffffffffffff16600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614610ac6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff16600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a36000600560016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b606060048054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610c495780601f10610c1e57610100808354040283529160200191610c49565b820191906000526020600020905b815481529060010190602001808311610c2c57829003601f168201915b5050505050905090565b610c5d82826117b2565b5050565b6000610d24610c6e610fe3565b84610d1f85604051806060016040528060258152602001611b0b6025913960016000610c98610fe3565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546114a39092919063ffffffff16565b610feb565b6001905092915050565b6000610d42610d3b610fe3565b84846111e2565b6001905092915050565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b610ddb610fe3565b73ffffffffffffffffffffffffffffffffffffffff16600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614610e9d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161415610f23576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526026815260200180611a0b6026913960400191505060405180910390fd5b8073ffffffffffffffffffffffffffffffffffffffff16600560019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a380600560016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b600033905090565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415611071576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526024815260200180611ae76024913960400191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156110f7576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526022815260200180611a316022913960400191505060405180910390fd5b80600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925836040518082815260200191505060405180910390a3505050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415611268576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526025815260200180611ac26025913960400191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156112ee576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260238152602001806119c66023913960400191505060405180910390fd5b6112f9838383611976565b61136481604051806060016040528060268152602001611a53602691396000808773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546114a39092919063ffffffff16565b6000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506113f7816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461156390919063ffffffff16565b6000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a3505050565b6000838311158290611550576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b838110156115155780820151818401526020810190506114fa565b50505050905090810190601f1680156115425780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b5060008385039050809150509392505050565b6000808284019050838110156115e1576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601b8152602001807f536166654d6174683a206164646974696f6e206f766572666c6f77000000000081525060200191505060405180910390fd5b8091505092915050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16141561168e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601f8152602001807f45524332303a206d696e7420746f20746865207a65726f20616464726573730081525060200191505060405180910390fd5b61169a60008383611976565b6116af8160025461156390919063ffffffff16565b600281905550611706816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461156390919063ffffffff16565b6000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a35050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415611838576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526021815260200180611aa16021913960400191505060405180910390fd5b61184482600083611976565b6118af816040518060600160405280602281526020016119e9602291396000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546114a39092919063ffffffff16565b6000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506119068160025461197b90919063ffffffff16565b600281905550600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a35050565b505050565b60006119bd83836040518060400160405280601e81526020017f536166654d6174683a207375627472616374696f6e206f766572666c6f7700008152506114a3565b90509291505056fe45524332303a207472616e7366657220746f20746865207a65726f206164647265737345524332303a206275726e20616d6f756e7420657863656564732062616c616e63654f776e61626c653a206e6577206f776e657220697320746865207a65726f206164647265737345524332303a20617070726f766520746f20746865207a65726f206164647265737345524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e636545524332303a207472616e7366657220616d6f756e74206578636565647320616c6c6f77616e636545524332303a206275726e2066726f6d20746865207a65726f206164647265737345524332303a207472616e736665722066726f6d20746865207a65726f206164647265737345524332303a20617070726f76652066726f6d20746865207a65726f206164647265737345524332303a2064656372656173656420616c6c6f77616e63652062656c6f77207a65726fa2646970667358221220f1ab638abebc83764e12479badf1f3b68bd67ce3eb7e4ad908b3919259d1917c64736f6c63430006060033000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000046475636b00000000000000000000000000000000000000000000000000000000"),
	).WithRawSignature(
		big.NewInt(2037),
		hexutil.MustDecodeBig("0x7d1de0b2c2c1f45fca480a84c37f66d0bc73735c176c15d70eb17e586a1feb59"),
		hexutil.MustDecodeBig("0x2afc639793cc1879d93adaa4c4ac9b01bf832b0e1f1ad4dce6cc85a553e7546a"),
	)

	// ref := types.NewContractCreation(
	// 	1,
	// 	big.NewInt(0),
	// 	644546,
	// 	big.NewInt(1000000000),
	// 	common.FromHex("0x608060405234801561001057600080fd5b50604051610ae3380380610ae38339818101604052602081101561003357600080fd5b8101908080519060200190929190505050806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050610a4f806100946000396000f3fe6080604052600436106100555760003560e01c806348c894911461005a5780635a281296146101225780639485d2931461018757806398791f72146101de578063f3fef3a3146102a6578063f435f5a714610301575b600080fd5b34801561006657600080fd5b506101206004803603602081101561007d57600080fd5b810190808035906020019064010000000081111561009a57600080fd5b8201836020820111156100ac57600080fd5b803590602001918460018302840111640100000000831117156100ce57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610345565b005b34801561012e57600080fd5b506101716004803603602081101561014557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610517565b6040518082815260200191505060405180910390f35b34801561019357600080fd5b5061019c61052f565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b3480156101ea57600080fd5b506102a46004803603602081101561020157600080fd5b810190808035906020019064010000000081111561021e57600080fd5b82018360208201111561023057600080fd5b8035906020019184600183028401116401000000008311171561025257600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610554565b005b3480156102b257600080fd5b506102ff600480360360408110156102c957600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610723565b005b6103436004803603602081101561031757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610835565b005b60008060008060608580602001905160a081101561036257600080fd5b8101908080519060200190929190805190602001909291908051906020019092919080519060200190929190805160405193929190846401000000008211156103aa57600080fd5b838201915060208201858111156103c057600080fd5b82518660018202830111640100000000821117156103dd57600080fd5b8083526020830192505050908051906020019080838360005b838110156104115780820151818401526020810190506103f6565b50505050905090810190601f16801561043e5780820380516001836020036101000a031916815260200191505b50604052505050945094509450945094506000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166340c10f1985856040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050600060405180830381600087803b1580156104f757600080fd5b505af115801561050b573d6000803e3d6000fd5b50505050505050505050565b60016020528060005260406000206000915090505481565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008060008060608580602001905160a081101561057157600080fd5b8101908080519060200190929190805190602001909291908051906020019092919080519060200190929190805160405193929190846401000000008211156105b957600080fd5b838201915060208201858111156105cf57600080fd5b82518660018202830111640100000000821117156105ec57600080fd5b8083526020830192505050908051906020019080838360005b83811015610620578082015181840152602081019050610605565b50505050905090810190601f16801561064d5780820380516001836020036101000a031916815260200191505b5060405250505094509450945094509450478311156106d4576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601d8152602001807f496e73756666696369656e742062616c616e636520776974686472617700000081525060200191505060405180910390fd5b8373ffffffffffffffffffffffffffffffffffffffff166108fc849081150290604051600060405180830381858888f1935050505015801561071a573d6000803e3d6000fd5b50505050505050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16639dc29fac33836040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050600060405180830381600087803b1580156107cb57600080fd5b505af11580156107df573d6000803e3d6000fd5b505050503373ffffffffffffffffffffffffffffffffffffffff167f992ee874049a42cae0757a765cd7f641b6028cc35c3478bde8330bf417c3a7a9826040518082815260200191505060405180910390a25050565b600034116108ab576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600d8152602001807f4c6f636b207a65726f206d61700000000000000000000000000000000000000081525060200191505060405180910390fd5b6108fd34600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461099190919063ffffffff16565b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055503373ffffffffffffffffffffffffffffffffffffffff167f9fe029c6176f2b9fe1394354b760728bc1b5fcc32f2e5f21f981fb7a65102ed6346040518082815260200191505060405180910390a250565b600080828401905083811015610a0f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601b8152602001807f536166654d6174683a206164646974696f6e206f766572666c6f77000000000081525060200191505060405180910390fd5b809150509291505056fea2646970667358221220718f21aa628ec657911ad74a98800cadb0510834958487054c295ec2205074e664736f6c6343000606003300000000000000000000000040fb23023b8bb73a19e949fa00ef3ccf7ee07bb6"),
	// ).WithRawSignature(
	// 	big.NewInt(2037),
	// 	hexutil.MustDecodeBig("0x71d17107d6edfa7d139203a66f7e6bbccc495fc28f07858bc7037a0c293b1c4c"),
	// 	hexutil.MustDecodeBig("0x7c326996e155a2cb82dd1f0f6c3e9766b043779db91f3d99f2d6e4f8eda3f7ed"),
	// )

	// ch := types.NewTransaction(
	// 	2,
	// 	common.HexToAddress("0x40FB23023B8Bb73a19e949FA00ef3CCF7EE07Bb6"),
	// 	big.NewInt(0),
	// 	31095,
	// 	big.NewInt(1000000000),
	// 	common.FromHex("f2fde38b0000000000000000000000005221538292372ca706a62eb0d4890d2c85543be9"),
	// ).WithRawSignature(
	// 	big.NewInt(2037),
	// 	hexutil.MustDecodeBig("0x2107930080ecee47b74b3ab91d36318c135eff4fc8a9ff0472c18ece47ce2c10"),
	// 	hexutil.MustDecodeBig("0x3a00a07a7de232c367d5722f41c5a854235fccf7ca2d511f77c30605936f5345"),
	// )

	// txs = append(txs, token, ref, ch)
	txs = append(txs, token)

	return txs
}

// copyReceipts makes a deep copy of the given receipts.
func copyReceipts(receipts []*types.Receipt) []*types.Receipt {
	result := make([]*types.Receipt, len(receipts))
	for i, l := range receipts {
		cpy := *l
		result[i] = &cpy
	}
	return result
}

// postSideBlock fires a side chain event, only use it for testing.
func (w *worker) postSideBlock(event core.ChainSideEvent) {
	select {
	case w.chainSideCh <- event:
	case <-w.exitCh:
	}
}
func (w *worker) requestCrossTxProof(txHash common.Hash) error {
	w.mux.Post(core.NewRequestTxProofEvent{TxHash: txHash})
	return nil
}

// totalFees computes total consumed fees in ETH. Block transactions and receipts have to have the same order.
func totalFees(block *types.Block, receipts []*types.Receipt) *big.Float {
	feesWei := new(big.Int)
	for i, tx := range block.Transactions() {
		feesWei.Add(feesWei, new(big.Int).Mul(new(big.Int).SetUint64(receipts[i].GasUsed), tx.GasPrice()))
	}
	return new(big.Float).Quo(new(big.Float).SetInt(feesWei), new(big.Float).SetInt(big.NewInt(params.Ether)))
}

func makeCMTransaction(tx *ulvp.UlvpTransaction, nonce uint64) *types.Transaction {
	encoded, _ := packTx(tx)
	cm := types.NewTransaction(nonce, types.RefToken, nil, 0, nil, encoded)
	return cm
}

func packTx(ulvpT *ulvp.UlvpTransaction) (packed []byte, err error) {
	tx := ulvpT.Tx

	// TODO: resolve signer from address
	fromAddr, sign_err := tx.OtherFrom()
	if sign_err != nil {
		return nil, sign_err
	}

	genabi := types.Genabi
	refabi := types.Refabi
	method, ref_err := refabi.MethodById(tx.Data())
	if err != nil {
		return nil, ref_err
	}

	proof, err := rlp.EncodeToBytes(ulvpT.SimpUlvpP)
	if err != nil {
		log.Error("EncodeToBytes lock proof failed", "error", err)
		return nil, err
	}

	if method.Name == "lock" {
		args := struct {
			Id      string
			Nation  string
			Name    string
			Address string
		}{}

		if err = method.Inputs.Unpack(&args, tx.Data()[4:]); err != nil {
			log.Warn("Decode CM lock failed", "error", err)
			return nil, err
		}
		log.Warn("CM lock map", "from", fromAddr, "value", tx.Value(), "tx", tx.Hash())

		packed, err = genabi.Pack("", fromAddr, fromAddr, tx.Value(), tx.Hash(), args.Id, args.Nation, args.Name, args.Address, proof)
		if err != nil {
			log.Error("Encode lock CM failed", "error", err)
			return nil, err
		}

		// Sign unlock transaction
		packed, err = refabi.Pack("unlock", packed)
		if err != nil {
			log.Error("Mint transaction encode error", "tx", tx.Hash())
			return nil, err
		}
	}

	if method.Name == "withdraw" {
		args := struct {
			Receiver common.Address
			Amount   *big.Int
		}{}

		if err = method.Inputs.Unpack(&args, tx.Data()[4:]); err != nil {
			log.Warn("Decode CM withdraw failed", "error", err)
			return nil, err
		}
		log.Warn("CM withdraw xmap", "from", fromAddr, "to", args.Receiver, "value", args.Amount, "tx", tx.Hash())

		// Sign withdrawxamp transaction
		packed, err = genabi.Pack("", fromAddr, args.Receiver, args.Amount, tx.Hash(), proof)
		if err != nil {
			log.Warn("Encode CM failed", "error", err)
			return nil, err
		}

		packed, err = refabi.Pack("withdrawXMap", packed)
		if err != nil {
			log.Error("Mint transaction encode error", "tx", tx.Hash())
			return nil, err
		}
	}

	return packed, nil
}
