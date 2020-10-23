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

package mos

import (
	"context"
	"errors"
	"math/big"

	"github.com/marcopoloprotoco/mouse/accounts"
	"github.com/marcopoloprotoco/mouse/common"
	"github.com/marcopoloprotoco/mouse/consensus"
	"github.com/marcopoloprotoco/mouse/core"
	"github.com/marcopoloprotoco/mouse/core/bloombits"
	"github.com/marcopoloprotoco/mouse/core/rawdb"
	"github.com/marcopoloprotoco/mouse/core/state"
	"github.com/marcopoloprotoco/mouse/core/types"
	"github.com/marcopoloprotoco/mouse/core/vm"
	"github.com/marcopoloprotoco/mouse/event"
	"github.com/marcopoloprotoco/mouse/miner"
	"github.com/marcopoloprotoco/mouse/mos/downloader"
	"github.com/marcopoloprotoco/mouse/mos/gasprice"
	"github.com/marcopoloprotoco/mouse/mosdb"
	"github.com/marcopoloprotoco/mouse/params"
	"github.com/marcopoloprotoco/mouse/rpc"
)

// EthAPIBackend implements ethapi.Backend for full nodes
type EthAPIBackend struct {
	extRPCEnabled bool
	mos           *Mouse
	gpo           *gasprice.Oracle
	crossTxs      map[common.Hash]*types.Transaction
	requestTxSub  *event.TypeMuxSubscription
}

// NewPublicEthereumAPI creates a new Mouse protocol API.
func NewEthAPIBackend(extRPCEnabled bool, mos *Mouse, gpo *gasprice.Oracle) *EthAPIBackend {

	backend := &EthAPIBackend{
		extRPCEnabled: extRPCEnabled,
		mos:           mos,
		gpo:           gpo,
		crossTxs:      make(map[common.Hash]*types.Transaction),
	}

	backend.requestTxSub = backend.mos.EventMux().Subscribe(core.NewCrossTxEvent{})
	go backend.requestCrossTx()

	return backend
}

// requestTxLoop sends mined blocks to connected peers.
func (pm *EthAPIBackend) requestCrossTx() {
	for obj := range pm.requestTxSub.Chan() {
		if ev, ok := obj.Data.(core.NewCrossTxEvent); ok {
			if _, ok := pm.crossTxs[ev.Hash]; !ok {
				pm.crossTxs[ev.Hash] = ev.Tx
			}
		}
	}
}

// ChainConfig returns the active chain configuration.
func (b *EthAPIBackend) ChainConfig() *params.ChainConfig {
	return b.mos.blockchain.Config()
}

func (b *EthAPIBackend) CurrentBlock() *types.Block {
	return b.mos.blockchain.CurrentBlock()
}

func (b *EthAPIBackend) SetHead(number uint64) {
	b.mos.protocolManager.downloader.Cancel()
	b.mos.blockchain.SetHead(number)
}

func (b *EthAPIBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	if number == rpc.PendingBlockNumber {
		block := b.mos.miner.PendingBlock()
		return block.Header(), nil
	}
	// Otherwise resolve and return the block
	if number == rpc.LatestBlockNumber {
		return b.mos.blockchain.CurrentBlock().Header(), nil
	}
	return b.mos.blockchain.GetHeaderByNumber(uint64(number)), nil
}

func (b *EthAPIBackend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.HeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.mos.blockchain.GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.mos.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		return header, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *EthAPIBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return b.mos.blockchain.GetHeaderByHash(hash), nil
}

func (b *EthAPIBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	// Pending block is only known by the miner
	if number == rpc.PendingBlockNumber {
		block := b.mos.miner.PendingBlock()
		return block, nil
	}
	// Otherwise resolve and return the block
	if number == rpc.LatestBlockNumber {
		return b.mos.blockchain.CurrentBlock(), nil
	}
	return b.mos.blockchain.GetBlockByNumber(uint64(number)), nil
}

func (b *EthAPIBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.mos.blockchain.GetBlockByHash(hash), nil
}

func (b *EthAPIBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.BlockByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.mos.blockchain.GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.mos.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		block := b.mos.blockchain.GetBlock(hash, header.Number.Uint64())
		if block == nil {
			return nil, errors.New("header found, but block body is missing")
		}
		return block, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *EthAPIBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if number == rpc.PendingBlockNumber {
		block, state := b.mos.miner.Pending()
		return state, block.Header(), nil
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	stateDb, err := b.mos.BlockChain().StateAt(header.Root)
	return stateDb, header, err
}

func (b *EthAPIBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.StateAndHeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, nil, err
		}
		if header == nil {
			return nil, nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.mos.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		stateDb, err := b.mos.BlockChain().StateAt(header.Root)
		return stateDb, header, err
	}
	return nil, nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *EthAPIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	return b.mos.blockchain.GetReceiptsByHash(hash), nil
}

func (b *EthAPIBackend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	receipts := b.mos.blockchain.GetReceiptsByHash(hash)
	if receipts == nil {
		return nil, nil
	}
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (b *EthAPIBackend) GetTd(ctx context.Context, hash common.Hash) *big.Int {
	return b.mos.blockchain.GetTdByHash(hash)
}

func (b *EthAPIBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header) (*vm.EVM, func() error, error) {
	vmError := func() error { return nil }

	context := core.NewEVMContext(msg, header, b.mos.BlockChain(), nil)
	return vm.NewEVM(context, state, b.mos.blockchain.Config(), *b.mos.blockchain.GetVMConfig()), vmError, nil
}

func (b *EthAPIBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.mos.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (b *EthAPIBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.mos.miner.SubscribePendingLogs(ch)
}

func (b *EthAPIBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.mos.BlockChain().SubscribeChainEvent(ch)
}

func (b *EthAPIBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.mos.BlockChain().SubscribeChainHeadEvent(ch)
}

func (b *EthAPIBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return b.mos.BlockChain().SubscribeChainSideEvent(ch)
}

func (b *EthAPIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.mos.BlockChain().SubscribeLogsEvent(ch)
}

func (b *EthAPIBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.mos.txPool.AddLocal(signedTx)
}

func (b *EthAPIBackend) GetPoolTransactions() (types.Transactions, error) {
	pending, err := b.mos.txPool.Pending()
	if err != nil {
		return nil, err
	}
	var txs types.Transactions
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	return txs, nil
}

func (b *EthAPIBackend) GetPoolTransaction(hash common.Hash) *types.Transaction {
	return b.mos.txPool.Get(hash)
}

func (b *EthAPIBackend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(b.mos.ChainDb(), txHash)
	return tx, blockHash, blockNumber, index, nil
}

func (b *EthAPIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.mos.txPool.Nonce(addr), nil
}

func (b *EthAPIBackend) Stats() (pending int, queued int) {
	return b.mos.txPool.Stats()
}

func (b *EthAPIBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.mos.TxPool().Content()
}

func (b *EthAPIBackend) TxPool() *core.TxPool {
	return b.mos.TxPool()
}

func (b *EthAPIBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return b.mos.TxPool().SubscribeNewTxsEvent(ch)
}

func (b *EthAPIBackend) GetCrossTransaction(hash common.Hash) (*types.Transaction, error) {
	if v, ok := b.crossTxs[hash]; ok {
		return v, nil
	}
	return nil, errors.New("cross transaction not find")
}

func (b *EthAPIBackend) Downloader() *downloader.Downloader {
	return b.mos.Downloader()
}

func (b *EthAPIBackend) ProtocolVersion() int {
	return b.mos.EthVersion()
}

func (b *EthAPIBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *EthAPIBackend) ChainDb() mosdb.Database {
	return b.mos.ChainDb()
}

func (b *EthAPIBackend) EventMux() *event.TypeMux {
	return b.mos.EventMux()
}

func (b *EthAPIBackend) AccountManager() *accounts.Manager {
	return b.mos.AccountManager()
}

func (b *EthAPIBackend) ExtRPCEnabled() bool {
	return b.extRPCEnabled
}

func (b *EthAPIBackend) RPCGasCap() uint64 {
	return b.mos.config.RPCGasCap
}

func (b *EthAPIBackend) RPCTxFeeCap() float64 {
	return b.mos.config.RPCTxFeeCap
}

func (b *EthAPIBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.mos.bloomIndexer.Sections()
	return params.BloomBitsBlocks, sections
}

func (b *EthAPIBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.mos.bloomRequests)
	}
}

func (b *EthAPIBackend) Engine() consensus.Engine {
	return b.mos.engine
}

func (b *EthAPIBackend) CurrentHeader() *types.Header {
	return b.mos.blockchain.CurrentHeader()
}

func (b *EthAPIBackend) Miner() *miner.Miner {
	return b.mos.Miner()
}

func (b *EthAPIBackend) StartMining(threads int) error {
	return b.mos.StartMining(threads)
}
