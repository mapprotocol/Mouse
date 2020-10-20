// Copyright 2014 The mouse Authors
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
	"fmt"
	"github.com/marcopoloprotoco/mouse/common/hexutil"
	"github.com/marcopoloprotoco/mouse/core/ulvp"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marcopoloprotoco/mouse/common"
	"github.com/marcopoloprotoco/mouse/consensus/ethash"
	"github.com/marcopoloprotoco/mouse/core"
	"github.com/marcopoloprotoco/mouse/core/forkid"
	"github.com/marcopoloprotoco/mouse/core/rawdb"
	"github.com/marcopoloprotoco/mouse/core/types"
	"github.com/marcopoloprotoco/mouse/core/vm"
	"github.com/marcopoloprotoco/mouse/crypto"
	"github.com/marcopoloprotoco/mouse/event"
	"github.com/marcopoloprotoco/mouse/mos/downloader"
	"github.com/marcopoloprotoco/mouse/p2p"
	"github.com/marcopoloprotoco/mouse/p2p/enode"
	"github.com/marcopoloprotoco/mouse/params"
	"github.com/marcopoloprotoco/mouse/rlp"
)

func init() {
	// log.Root().SetHandler(log.LvlFilterHandler(log.LvlTrace, log.StreamHandler(os.Stderr, log.TerminalFormat(false))))
}

var testAccount, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")

// Tests that handshake failures are detected and reported correctly.
func TestStatusMsgErrors63(t *testing.T) {
	pm, _ := newTestProtocolManagerMust(t, downloader.FullSync, 0, nil, nil)
	var (
		genesis = pm.blockchain.Genesis()
		head    = pm.blockchain.CurrentHeader()
		td      = pm.blockchain.GetTd(head.Hash(), head.Number.Uint64())
	)
	defer pm.Stop()

	tests := []struct {
		code      uint64
		data      interface{}
		wantError error
	}{
		{
			code: TransactionMsg, data: []interface{}{},
			wantError: errResp(ErrNoStatusMsg, "first msg has code 2 (!= 0)"),
		},
		{
			code: StatusMsg, data: statusData63{10, DefaultConfig.NetworkId, td, head.Hash(), genesis.Hash()},
			wantError: errResp(ErrProtocolVersionMismatch, "10 (!= %d)", 63),
		},
		{
			code: StatusMsg, data: statusData63{63, 999, td, head.Hash(), genesis.Hash()},
			wantError: errResp(ErrNetworkIDMismatch, "999 (!= %d)", DefaultConfig.NetworkId),
		},
		{
			code: StatusMsg, data: statusData63{63, DefaultConfig.NetworkId, td, head.Hash(), common.Hash{3}},
			wantError: errResp(ErrGenesisMismatch, "0300000000000000 (!= %x)", genesis.Hash().Bytes()[:8]),
		},
	}
	for i, test := range tests {
		p, errc := newTestPeer("peer", 63, pm, false)
		// The send call might hang until reset because
		// the protocol might not read the payload.
		go p2p.Send(p.app, test.code, test.data)

		select {
		case err := <-errc:
			if err == nil {
				t.Errorf("test %d: protocol returned nil error, want %q", i, test.wantError)
			} else if err.Error() != test.wantError.Error() {
				t.Errorf("test %d: wrong error: got %q, want %q", i, err, test.wantError)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("protocol did not shut down within 2 seconds")
		}
		p.close()
	}
}

func TestStatusMsgErrors64(t *testing.T) {
	pm, _ := newTestProtocolManagerMust(t, downloader.FullSync, 0, nil, nil)
	var (
		genesis = pm.blockchain.Genesis()
		head    = pm.blockchain.CurrentHeader()
		td      = pm.blockchain.GetTd(head.Hash(), head.Number.Uint64())
		forkID  = forkid.NewID(pm.blockchain)
	)
	defer pm.Stop()

	tests := []struct {
		code      uint64
		data      interface{}
		wantError error
	}{
		{
			code: TransactionMsg, data: []interface{}{},
			wantError: errResp(ErrNoStatusMsg, "first msg has code 2 (!= 0)"),
		},
		{
			code: StatusMsg, data: statusData{10, DefaultConfig.NetworkId, td, head.Hash(), genesis.Hash(), forkID, nil},
			wantError: errResp(ErrProtocolVersionMismatch, "10 (!= %d)", 64),
		},
		{
			code: StatusMsg, data: statusData{64, 999, td, head.Hash(), genesis.Hash(), forkID, nil},
			wantError: errResp(ErrNetworkIDMismatch, "999 (!= %d)", DefaultConfig.NetworkId),
		},
		{
			code: StatusMsg, data: statusData{64, DefaultConfig.NetworkId, td, head.Hash(), common.Hash{3}, forkID, nil},
			wantError: errResp(ErrGenesisMismatch, "0300000000000000000000000000000000000000000000000000000000000000 (!= %x)", genesis.Hash()),
		},
		{
			code: StatusMsg, data: statusData{64, DefaultConfig.NetworkId, td, head.Hash(), genesis.Hash(), forkid.ID{Hash: [4]byte{0x00, 0x01, 0x02, 0x03}}, nil},
			wantError: errResp(ErrForkIDRejected, forkid.ErrLocalIncompatibleOrStale.Error()),
		},
	}
	for i, test := range tests {
		p, errc := newTestPeer("peer", 64, pm, false)
		// The send call might hang until reset because
		// the protocol might not read the payload.
		go p2p.Send(p.app, test.code, test.data)

		select {
		case err := <-errc:
			if err == nil {
				t.Errorf("test %d: protocol returned nil error, want %q", i, test.wantError)
			} else if err.Error() != test.wantError.Error() {
				t.Errorf("test %d: wrong error: got %q, want %q", i, err, test.wantError)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("protocol did not shut down within 2 seconds")
		}
		p.close()
	}
}

func TestForkIDSplit(t *testing.T) {
	var (
		engine = ethash.NewFaker()

		configNoFork  = &params.ChainConfig{HomesteadBlock: big.NewInt(1)}
		configProFork = &params.ChainConfig{
			HomesteadBlock: big.NewInt(1),
			EIP150Block:    big.NewInt(2),
			EIP155Block:    big.NewInt(2),
			EIP158Block:    big.NewInt(2),
			ByzantiumBlock: big.NewInt(3),
		}
		dbNoFork  = rawdb.NewMemoryDatabase()
		dbProFork = rawdb.NewMemoryDatabase()

		gspecNoFork  = &core.Genesis{Config: configNoFork}
		gspecProFork = &core.Genesis{Config: configProFork}

		genesisNoFork  = gspecNoFork.MustCommit(dbNoFork)
		genesisProFork = gspecProFork.MustCommit(dbProFork)

		chainNoFork, _  = core.NewBlockChain(dbNoFork, nil, configNoFork, engine, vm.Config{}, nil, nil)
		chainProFork, _ = core.NewBlockChain(dbProFork, nil, configProFork, engine, vm.Config{}, nil, nil)

		blocksNoFork, _  = core.GenerateChain(configNoFork, genesisNoFork, engine, dbNoFork, 2, nil)
		blocksProFork, _ = core.GenerateChain(configProFork, genesisProFork, engine, dbProFork, 2, nil)

		ethNoFork, _  = NewProtocolManager(configNoFork, nil, downloader.FullSync, 1, new(event.TypeMux), &testTxPool{pool: make(map[common.Hash]*types.Transaction)}, engine, chainNoFork, dbNoFork, 1, nil, nil)
		ethProFork, _ = NewProtocolManager(configProFork, nil, downloader.FullSync, 1, new(event.TypeMux), &testTxPool{pool: make(map[common.Hash]*types.Transaction)}, engine, chainProFork, dbProFork, 1, nil, nil)
	)
	ethNoFork.Start(1000)
	ethProFork.Start(1000)

	// Both nodes should allow the other to connect (same genesis, next fork is the same)
	p2pNoFork, p2pProFork := p2p.MsgPipe()
	peerNoFork := newPeer(64, p2p.NewPeer(enode.ID{1}, "", nil), p2pNoFork, nil)
	peerProFork := newPeer(64, p2p.NewPeer(enode.ID{2}, "", nil), p2pProFork, nil)

	errc := make(chan error, 2)
	go func() { errc <- ethNoFork.handle(peerProFork) }()
	go func() { errc <- ethProFork.handle(peerNoFork) }()

	select {
	case err := <-errc:
		t.Fatalf("frontier nofork <-> profork failed: %v", err)
	case <-time.After(250 * time.Millisecond):
		p2pNoFork.Close()
		p2pProFork.Close()
	}
	// Progress into Homestead. Fork's match, so we don't care what the future holds
	chainNoFork.InsertChain(blocksNoFork[:1])
	chainProFork.InsertChain(blocksProFork[:1])

	p2pNoFork, p2pProFork = p2p.MsgPipe()
	peerNoFork = newPeer(64, p2p.NewPeer(enode.ID{1}, "", nil), p2pNoFork, nil)
	peerProFork = newPeer(64, p2p.NewPeer(enode.ID{2}, "", nil), p2pProFork, nil)

	errc = make(chan error, 2)
	go func() { errc <- ethNoFork.handle(peerProFork) }()
	go func() { errc <- ethProFork.handle(peerNoFork) }()

	select {
	case err := <-errc:
		t.Fatalf("homestead nofork <-> profork failed: %v", err)
	case <-time.After(250 * time.Millisecond):
		p2pNoFork.Close()
		p2pProFork.Close()
	}
	// Progress into Spurious. Forks mismatch, signalling differing chains, reject
	chainNoFork.InsertChain(blocksNoFork[1:2])
	chainProFork.InsertChain(blocksProFork[1:2])

	p2pNoFork, p2pProFork = p2p.MsgPipe()
	peerNoFork = newPeer(64, p2p.NewPeer(enode.ID{1}, "", nil), p2pNoFork, nil)
	peerProFork = newPeer(64, p2p.NewPeer(enode.ID{2}, "", nil), p2pProFork, nil)

	errc = make(chan error, 2)
	go func() { errc <- ethNoFork.handle(peerProFork) }()
	go func() { errc <- ethProFork.handle(peerNoFork) }()

	select {
	case err := <-errc:
		if want := errResp(ErrForkIDRejected, forkid.ErrLocalIncompatibleOrStale.Error()); err.Error() != want.Error() {
			t.Fatalf("fork ID rejection error mismatch: have %v, want %v", err, want)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("split peers not rejected")
	}
}

// This test checks that received transactions are added to the local pool.
func TestRecvTransactions63(t *testing.T) { testRecvTransactions(t, 63) }
func TestRecvTransactions64(t *testing.T) { testRecvTransactions(t, 64) }
func TestRecvTransactions65(t *testing.T) { testRecvTransactions(t, 65) }

func testRecvTransactions(t *testing.T, protocol int) {
	txAdded := make(chan []*types.Transaction)
	pm, _ := newTestProtocolManagerMust(t, downloader.FullSync, 0, nil, txAdded)
	pm.acceptTxs = 1 // mark synced to accept transactions
	p, _ := newTestPeer("peer", protocol, pm, true)
	defer pm.Stop()
	defer p.close()

	tx := newTestTransaction(testAccount, 0, 0)
	if err := p2p.Send(p.app, TransactionMsg, []interface{}{tx}); err != nil {
		t.Fatalf("send error: %v", err)
	}
	select {
	case added := <-txAdded:
		if len(added) != 1 {
			t.Errorf("wrong number of added transactions: got %d, want 1", len(added))
		} else if added[0].Hash() != tx.Hash() {
			t.Errorf("added wrong tx hash: got %v, want %v", added[0].Hash(), tx.Hash())
		}
	case <-time.After(2 * time.Second):
		t.Errorf("no NewTxsEvent received within 2 seconds")
	}
}

// This test checks that pending transactions are sent.
func TestSendTransactions63(t *testing.T) { testSendTransactions(t, 63) }
func TestSendTransactions64(t *testing.T) { testSendTransactions(t, 64) }
func TestSendTransactions65(t *testing.T) { testSendTransactions(t, 65) }

func testSendTransactions(t *testing.T, protocol int) {
	pm, _ := newTestProtocolManagerMust(t, downloader.FullSync, 0, nil, nil)
	defer pm.Stop()

	// Fill the pool with big transactions (use a subscription to wait until all
	// the transactions are announced to avoid spurious events causing extra
	// broadcasts).
	const txsize = txsyncPackSize / 10
	alltxs := make([]*types.Transaction, 100)
	for nonce := range alltxs {
		alltxs[nonce] = newTestTransaction(testAccount, uint64(nonce), txsize)
	}
	pm.txpool.AddRemotes(alltxs)
	time.Sleep(100 * time.Millisecond) // Wait until new tx even gets out of the system (lame)

	// Connect several peers. They should all receive the pending transactions.
	var wg sync.WaitGroup
	checktxs := func(p *testPeer) {
		defer wg.Done()
		defer p.close()
		seen := make(map[common.Hash]bool)
		for _, tx := range alltxs {
			seen[tx.Hash()] = false
		}
		for n := 0; n < len(alltxs) && !t.Failed(); {
			var forAllHashes func(callback func(hash common.Hash))
			switch protocol {
			case 63:
				fallthrough
			case 64:
				msg, err := p.app.ReadMsg()
				if err != nil {
					t.Errorf("%v: read error: %v", p.Peer, err)
					continue
				} else if msg.Code != TransactionMsg {
					t.Errorf("%v: got code %d, want TxMsg", p.Peer, msg.Code)
					continue
				}
				var txs []*types.Transaction
				if err := msg.Decode(&txs); err != nil {
					t.Errorf("%v: %v", p.Peer, err)
					continue
				}
				forAllHashes = func(callback func(hash common.Hash)) {
					for _, tx := range txs {
						callback(tx.Hash())
					}
				}
			case 65:
				msg, err := p.app.ReadMsg()
				if err != nil {
					t.Errorf("%v: read error: %v", p.Peer, err)
					continue
				} else if msg.Code != NewPooledTransactionHashesMsg {
					t.Errorf("%v: got code %d, want NewPooledTransactionHashesMsg", p.Peer, msg.Code)
					continue
				}
				var hashes []common.Hash
				if err := msg.Decode(&hashes); err != nil {
					t.Errorf("%v: %v", p.Peer, err)
					continue
				}
				forAllHashes = func(callback func(hash common.Hash)) {
					for _, h := range hashes {
						callback(h)
					}
				}
			}
			forAllHashes(func(hash common.Hash) {
				seentx, want := seen[hash]
				if seentx {
					t.Errorf("%v: got tx more than once: %x", p.Peer, hash)
				}
				if !want {
					t.Errorf("%v: got unexpected tx: %x", p.Peer, hash)
				}
				seen[hash] = true
				n++
			})
		}
	}
	for i := 0; i < 3; i++ {
		p, _ := newTestPeer(fmt.Sprintf("peer #%d", i), protocol, pm, true)
		wg.Add(1)
		go checktxs(p)
	}
	wg.Wait()
}

func TestTransactionPropagation(t *testing.T)  { testSyncTransaction(t, true) }
func TestTransactionAnnouncement(t *testing.T) { testSyncTransaction(t, false) }

func testSyncTransaction(t *testing.T, propagtion bool) {
	// Create a protocol manager for transaction fetcher and sender
	pmFetcher, _ := newTestProtocolManagerMust(t, downloader.FastSync, 0, nil, nil)
	defer pmFetcher.Stop()
	pmSender, _ := newTestProtocolManagerMust(t, downloader.FastSync, 1024, nil, nil)
	pmSender.broadcastTxAnnouncesOnly = !propagtion
	defer pmSender.Stop()

	// Sync up the two peers
	io1, io2 := p2p.MsgPipe()

	go pmSender.handle(pmSender.newPeer(65, p2p.NewPeer(enode.ID{}, "sender", nil), io2, pmSender.txpool.Get))
	go pmFetcher.handle(pmFetcher.newPeer(65, p2p.NewPeer(enode.ID{}, "fetcher", nil), io1, pmFetcher.txpool.Get))

	time.Sleep(250 * time.Millisecond)
	pmFetcher.doSync(peerToSyncOp(downloader.FullSync, pmFetcher.peers.BestPeer()))
	atomic.StoreUint32(&pmFetcher.acceptTxs, 1)

	newTxs := make(chan core.NewTxsEvent, 1024)
	sub := pmFetcher.txpool.SubscribeNewTxsEvent(newTxs)
	defer sub.Unsubscribe()

	// Fill the pool with new transactions
	alltxs := make([]*types.Transaction, 1024)
	for nonce := range alltxs {
		alltxs[nonce] = newTestTransaction(testAccount, uint64(nonce), 0)
	}
	pmSender.txpool.AddRemotes(alltxs)

	var got int
loop:
	for {
		select {
		case ev := <-newTxs:
			got += len(ev.Txs)
			if got == 1024 {
				break loop
			}
		case <-time.NewTimer(time.Second).C:
			t.Fatal("Failed to retrieve all transaction")
		}
	}
}

// Tests that the custom union field encoder and decoder works correctly.
func TestGetBlockHeadersDataEncodeDecode(t *testing.T) {
	// Create a "random" hash for testing
	var hash common.Hash
	for i := range hash {
		hash[i] = byte(i)
	}
	// Assemble some table driven tests
	tests := []struct {
		packet *getBlockHeadersData
		fail   bool
	}{
		// Providing the origin as either a hash or a number should both work
		{fail: false, packet: &getBlockHeadersData{Origin: hashOrNumber{Number: 314}}},
		{fail: false, packet: &getBlockHeadersData{Origin: hashOrNumber{Hash: hash}}},

		// Providing arbitrary query field should also work
		{fail: false, packet: &getBlockHeadersData{Origin: hashOrNumber{Number: 314}, Amount: 314, Skip: 1, Reverse: true}},
		{fail: false, packet: &getBlockHeadersData{Origin: hashOrNumber{Hash: hash}, Amount: 314, Skip: 1, Reverse: true}},

		// Providing both the origin hash and origin number must fail
		{fail: true, packet: &getBlockHeadersData{Origin: hashOrNumber{Hash: hash, Number: 314}}},
	}
	// Iterate over each of the tests and try to encode and then decode
	for i, tt := range tests {
		bytes, err := rlp.EncodeToBytes(tt.packet)
		if err != nil && !tt.fail {
			t.Fatalf("test %d: failed to encode packet: %v", i, err)
		} else if err == nil && tt.fail {
			t.Fatalf("test %d: encode should have failed", i)
		}
		if !tt.fail {
			packet := new(getBlockHeadersData)
			if err := rlp.DecodeBytes(bytes, packet); err != nil {
				t.Fatalf("test %d: failed to decode packet: %v", i, err)
			}
			if packet.Origin.Hash != tt.packet.Origin.Hash || packet.Origin.Number != tt.packet.Origin.Number || packet.Amount != tt.packet.Amount ||
				packet.Skip != tt.packet.Skip || packet.Reverse != tt.packet.Reverse {
				t.Fatalf("test %d: encode decode mismatch: have %+v, want %+v", i, packet, tt.packet)
			}
		}
	}
}

func TestUVLPRLP(t *testing.T) {
	var (
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		key2, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
		key3, _ = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
		addr2   = crypto.PubkeyToAddress(key2.PublicKey)
		addr3   = crypto.PubkeyToAddress(key3.PublicKey)
		db      = rawdb.NewMemoryDatabase()
	)
	i, _ := new(big.Int).SetString("900000000000000000000000000", 10)

	// Ensure that key1 has some funds in the genesis block.
	gspec := &core.Genesis{
		Config: params.MouseChainConfig,
		Alloc: core.GenesisAlloc{
			addr1: {Balance: big.NewInt(1000000000)},
			common.HexToAddress("0x29341495424d182c10E0c4360c19E29B2bA88354"): {Balance: i},
			common.HexToAddress("0x9C238B78ddC24554FCB5d791709102EBcBf69d86"): {Balance: i},
			common.HexToAddress("0x78C530f8F316520133557Ed82A2c964D600C88B5"): {Balance: i},
			common.HexToAddress("0x81220F9CDf63c04F877f620328A4873F1Cc09038"): {Balance: i},
		},
	}
	genesis := gspec.MustCommit(db)

	// This call generates a chain of 5 blocks. The function runs for
	// each block and adds different features to gen based on the
	// block index.
	signer := types.HomesteadSigner{}
	chain, _ := core.GenerateChain(gspec.Config, genesis, ethash.NewFaker(), db, 100, func(i int, gen *core.BlockGen) {
		switch i {
		case 0:
			// In block 1, addr1 sends addr2 some ether.
			tx, _ := types.SignTx(types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(10000), params.TxGas, nil, nil), signer, key1)
			gen.AddTx(tx)
		case 1:
			// In block 2, addr1 sends some more ether to addr2.
			// addr2 passes it on to addr3.
			tx1, _ := types.SignTx(types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(1000), params.TxGas, nil, nil), signer, key1)
			tx2, _ := types.SignTx(types.NewTransaction(gen.TxNonce(addr2), addr3, big.NewInt(1000), params.TxGas, nil, nil), signer, key2)
			gen.AddTx(tx1)
			gen.AddTx(tx2)
		case 2:
			// Block 3 is empty but was mined by addr3.
			gen.SetCoinbase(addr3)
			gen.SetExtra([]byte("yeehaw"))
		case 3:
			// Block 4 includes blocks 2 and 3 as uncle headers (with modified extra data).
			b2 := gen.PrevBlock(1).Header()
			b2.Extra = []byte("foo")
			gen.AddUncle(b2)
			b3 := gen.PrevBlock(2).Header()
			b3.Extra = []byte("foo")
			gen.AddUncle(b3)
		case 4:
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
			gen.AddTx(token)

			ref := types.NewContractCreation(
				1,
				big.NewInt(0),
				644546,
				big.NewInt(1000000000),
				common.FromHex("0x608060405234801561001057600080fd5b50604051610ae3380380610ae38339818101604052602081101561003357600080fd5b8101908080519060200190929190505050806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050610a4f806100946000396000f3fe6080604052600436106100555760003560e01c806348c894911461005a5780635a281296146101225780639485d2931461018757806398791f72146101de578063f3fef3a3146102a6578063f435f5a714610301575b600080fd5b34801561006657600080fd5b506101206004803603602081101561007d57600080fd5b810190808035906020019064010000000081111561009a57600080fd5b8201836020820111156100ac57600080fd5b803590602001918460018302840111640100000000831117156100ce57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610345565b005b34801561012e57600080fd5b506101716004803603602081101561014557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610517565b6040518082815260200191505060405180910390f35b34801561019357600080fd5b5061019c61052f565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b3480156101ea57600080fd5b506102a46004803603602081101561020157600080fd5b810190808035906020019064010000000081111561021e57600080fd5b82018360208201111561023057600080fd5b8035906020019184600183028401116401000000008311171561025257600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610554565b005b3480156102b257600080fd5b506102ff600480360360408110156102c957600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610723565b005b6103436004803603602081101561031757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610835565b005b60008060008060608580602001905160a081101561036257600080fd5b8101908080519060200190929190805190602001909291908051906020019092919080519060200190929190805160405193929190846401000000008211156103aa57600080fd5b838201915060208201858111156103c057600080fd5b82518660018202830111640100000000821117156103dd57600080fd5b8083526020830192505050908051906020019080838360005b838110156104115780820151818401526020810190506103f6565b50505050905090810190601f16801561043e5780820380516001836020036101000a031916815260200191505b50604052505050945094509450945094506000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166340c10f1985856040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050600060405180830381600087803b1580156104f757600080fd5b505af115801561050b573d6000803e3d6000fd5b50505050505050505050565b60016020528060005260406000206000915090505481565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008060008060608580602001905160a081101561057157600080fd5b8101908080519060200190929190805190602001909291908051906020019092919080519060200190929190805160405193929190846401000000008211156105b957600080fd5b838201915060208201858111156105cf57600080fd5b82518660018202830111640100000000821117156105ec57600080fd5b8083526020830192505050908051906020019080838360005b83811015610620578082015181840152602081019050610605565b50505050905090810190601f16801561064d5780820380516001836020036101000a031916815260200191505b5060405250505094509450945094509450478311156106d4576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601d8152602001807f496e73756666696369656e742062616c616e636520776974686472617700000081525060200191505060405180910390fd5b8373ffffffffffffffffffffffffffffffffffffffff166108fc849081150290604051600060405180830381858888f1935050505015801561071a573d6000803e3d6000fd5b50505050505050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16639dc29fac33836040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050600060405180830381600087803b1580156107cb57600080fd5b505af11580156107df573d6000803e3d6000fd5b505050503373ffffffffffffffffffffffffffffffffffffffff167f992ee874049a42cae0757a765cd7f641b6028cc35c3478bde8330bf417c3a7a9826040518082815260200191505060405180910390a25050565b600034116108ab576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600d8152602001807f4c6f636b207a65726f206d61700000000000000000000000000000000000000081525060200191505060405180910390fd5b6108fd34600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461099190919063ffffffff16565b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055503373ffffffffffffffffffffffffffffffffffffffff167f9fe029c6176f2b9fe1394354b760728bc1b5fcc32f2e5f21f981fb7a65102ed6346040518082815260200191505060405180910390a250565b600080828401905083811015610a0f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601b8152602001807f536166654d6174683a206164646974696f6e206f766572666c6f77000000000081525060200191505060405180910390fd5b809150509291505056fea2646970667358221220718f21aa628ec657911ad74a98800cadb0510834958487054c295ec2205074e664736f6c6343000606003300000000000000000000000040fb23023b8bb73a19e949fa00ef3ccf7ee07bb6"),
			).WithRawSignature(
				big.NewInt(2035),
				hexutil.MustDecodeBig("0xeb1418299ef79258f43c31011a214249bc02a1cf5b95b27f14eb9a12b6db64b"),
				hexutil.MustDecodeBig("0x6e72a8ab0fa41cf65783b70c0ae51ee824bd1e450386725fc143cb8bf53424ee"),
			)
			gen.AddTx(ref)

			ch := types.NewTransaction(
				2,
				common.HexToAddress("0x40FB23023B8Bb73a19e949FA00ef3CCF7EE07Bb6"),
				big.NewInt(0),
				31095,
				big.NewInt(1000000000),
				common.FromHex("f2fde38b0000000000000000000000005221538292372ca706a62eb0d4890d2c85543be9"),
			).WithRawSignature(
				big.NewInt(2035),
				hexutil.MustDecodeBig("0x6a78a08d301d8d30a46f6cc98a7da3d8fd73b40e7fa50dbbb5571c803dcca2d3"),
				hexutil.MustDecodeBig("0x4e2a0356f4d219110a85b4fd8172ffcbddd1f9032c765dc295b26254604bb377"),
			)
			gen.AddTx(ch)
		case 5:
			proof := getRandomData()
			fmt.Println("data ", len(proof)/1024/1024)
			packed, err := types.Genabi.Pack("", addr1, addr2, new(big.Int).SetUint64(10), common.Hash{}, proof)
			if err != nil {
				fmt.Println("Encode lock CM failed", "error", err)
			}

			// Sign unlock transaction
			packed, err = types.Refabi.Pack("unlock", packed)
			if err != nil {
				fmt.Println("Mint transaction encode error", "tx", err)
			}
			cm := types.NewTransaction(0, types.RefToken, nil, 0, nil, packed)
			gen.AddTx(cm)

		case 49:
			// In block 1, addr1 sends addr2 some ether.
			tx, _ := types.SignTx(types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(10000), params.TxGas, nil, nil), signer, key1)
			gen.AddTx(tx)
		}
	})

	// Import the chain. This runs all block validation rules.
	blockchain, _ := core.NewBlockChain(db, nil, gspec.Config, ethash.NewFaker(), vm.Config{}, nil, nil)
	defer blockchain.Stop()

	if i, err := blockchain.InsertChain(chain); err != nil {
		fmt.Printf("insert error (block %d): %v\n", chain[i].NumberU64(), err)
		return
	}
	blockchain.UlVP.InitOtherChain(genesis)

	txhash := blockchain.GetBlockByNumber(50).Transactions()[0].Hash()
	fmt.Println("blockchain", blockchain.CurrentBlock().Number(), " txs ", len(blockchain.GetBlockByNumber(50).Transactions()))

	var mtProof ulvp.SimpleUlvpProof
	receiptRep, receipt, err := blockchain.UlVP.GetReceiptProof(txhash)

	if err != nil {
		fmt.Println("GetReceiptProof err", err)
	}
	dataRes, err := blockchain.UlVP.HandleSimpleUlvpMsgReq(blockchain.UlVP.GetSimpleUlvpMsgReq([]uint64{receipt.BlockNumber.Uint64(), blockchain.CurrentBlock().NumberU64()}))

	if err != nil {
		fmt.Println("HandleSimpleUlvpMsgReq err", err)
	}

	mtProof.Result = true
	mtProof.ReceiptProof = receiptRep
	mtProof.ChainProof = &ulvp.UlvpChainProof{
		Res: dataRes,
	}
	mtProof.Header = blockchain.GetHeaderByHash(receipt.BlockHash)
	mtProof.End = blockchain.CurrentBlock().Number()
	mtProof.TxHash = txhash

	size, proofD, err := rlp.EncodeToReader(&mtProof)
	if err != nil {
		fmt.Println("err", err)
	}

	var request *ulvp.SimpleUlvpProof

	s := rlp.NewStream(proofD, uint64(size))
	if err := s.Decode(&request); err != nil {
		fmt.Println("err", err)
	}
	request.ChainProof = blockchain.UlVP.MakeUvlpChainProof(request.ChainProof.Res)
	if _, err = request.VerifyULVPTXMsg(request.TxHash); err != nil {
		fmt.Println("VerifyULVPTXMsg err", err)
	}
}

func getRandomData() []byte {
	data0 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	data := []byte{}
	for i := 0; i < 1000; i++ {
		data = append(data, data0...)
	}
	return data
}

func TestPeer_SendMMRReceiptProof(t *testing.T) {

	var data []rlp.RawValue
	data = append(data, []byte{1, 2})
	pReceipt := &ulvp.ReceiptTrieResps{Proofs: data, Index: 1, ReceiptHash: common.Hash{}}

	size, proofD, err := rlp.EncodeToReader(pReceipt)
	if err != nil {
		fmt.Println("err", err)
	}

	var request ulvp.ReceiptTrieResps

	s := rlp.NewStream(proofD, uint64(size))
	if err := s.Decode(&request); err != nil {
		fmt.Println("err", err)
	}
}
