package core

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/marcopoloprotoco/mouse/common"
	"github.com/marcopoloprotoco/mouse/trie"
	"math/big"
	"sort"
	// "github.com/marcopoloprotoco/mouse/common"
	"github.com/marcopoloprotoco/mouse/core/types"
	"github.com/marcopoloprotoco/mouse/core/ulvp"
	"github.com/marcopoloprotoco/mouse/rlp"
	// "golang.org/x/crypto/sha3"
)

var (
	K                = 3
	Ulvp *SimpleULVP = nil
)

func Uint64SliceEqual(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	if (a == nil) != (b == nil) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
func Uint64SliceHas(origin, sub []uint64) bool {
	for _, v := range sub {
		found := false
		for _, v2 := range origin {
			if v == v2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func ParseBaseReqUlvpMsg(data []byte) (*ulvp.BaseReqUlvpMsg, error) {
	obj := &ulvp.BaseReqUlvpMsg{}
	err := rlp.DecodeBytes(data, obj)
	return obj, err
}
func makeFirstBaseUlvpMsg() *ulvp.BaseReqUlvpMsg {
	return &ulvp.BaseReqUlvpMsg{
		Check: []uint64{0},
		Right: big.NewInt(0),
	}
}

func ParseUlvpMsgReq(data []byte) (*ulvp.UlvpMsgReq, error) {
	obj := &ulvp.UlvpMsgReq{}
	err := rlp.DecodeBytes(data, obj)
	return obj, err
}
func makeUlvpMsgReq(blocks []uint64) *ulvp.UlvpMsgReq {
	return &ulvp.UlvpMsgReq{
		FirstReq: makeFirstBaseUlvpMsg(),
		SecondReq: &ulvp.BaseReqUlvpMsg{
			Check: blocks,
		},
	}
}

func ParseProofMsg(data []byte) (*ulvp.ChainHeaderProofMsg, error) {
	obj := &ulvp.ChainHeaderProofMsg{}
	err := rlp.DecodeBytes(data, obj)
	return obj, err
}

func ParseUvlpMsgRes(data []byte) (*ulvp.UlvpMsgRes, error) {
	obj := &ulvp.UlvpMsgRes{}
	err := rlp.DecodeBytes(data, obj)
	return obj, err
}

func getRightDifficult(localChain *BlockChain, curNum uint64, r *big.Int) (*big.Int, []*types.Header) {
	heads := []*types.Header{}
	i := int(curNum - uint64(K))
	if i < 0 {
		i = 0
	}

	right := new(big.Int).Set(r)
	for ; i <= int(curNum); i++ {
		b := localChain.GetBlockByNumber(uint64(i))
		if b != nil {
			heads = append(heads, b.Header())
			right = new(big.Int).Add(right, b.Difficulty())
		}
	}
	return right, heads
}

func PushBlock(mm *ulvp.Mmr, b *types.Block, time uint64, check bool) error {
	d := b.Difficulty()
	n := ulvp.NewNode(b.Hash(), d, new(big.Int).Set(d), big.NewInt(0), time)

	if check {
		mmrLocal, mmrRemote := mm.GetRoot2(), b.MmrRoot()
		if !bytes.Equal(mmrLocal[:], mmrRemote[:]) {
			return errors.New(fmt.Sprintf("mmr root not match,height:%v,local:%v,remote:%v", b.NumberU64(), hex.EncodeToString(mmrLocal[:]), hex.EncodeToString(mmrRemote[:])))
		}
	}
	mm.Push(n)
	return nil
}

/////////////////////////////////////////////////////////////////////////////////////

type SimpleULVP struct {
	MmrInfo     *ulvp.Mmr
	localChain  *BlockChain
	RemoteChain *ulvp.OtherChainAdapter
}

func NewSimpleULVP(l *BlockChain) *SimpleULVP {
	Ulvp = &SimpleULVP{
		MmrInfo:    ulvp.NewMMR(),
		localChain: l,
	}
	return Ulvp
}

func (uv *SimpleULVP) InitOtherChain(other *types.Block) {
	r := &ulvp.OtherChainAdapter{Genesis: other.Hash()}
	uv.RemoteChain = r
}

func (uv *SimpleULVP) GetFirstMsg() *ulvp.BaseReqUlvpMsg {
	return makeFirstBaseUlvpMsg()
}

func (uv *SimpleULVP) PushFirstMsg() ([]byte, error) {
	cur := uv.localChain.CurrentBlockHeader()
	curNum := cur.Number.Uint64()
	genesis := uv.localChain.GetBlockByNumber(0)
	if curNum == 0 {
		res := &ulvp.ChainHeaderProofMsg{
			Proof:  &ulvp.ProofInfo{},
			Header: []*types.Header{genesis.Header()},
			Right:  new(big.Int).SetUint64(0),
		}
		return res.Datas()
	}

	Right, heads := getRightDifficult(uv.localChain, curNum, new(big.Int).Set(cur.Difficulty))
	proof, _, _ := uv.MmrInfo.CreateNewProof(Right)
	heads = append([]*types.Header{genesis.Header(), cur}, heads...)

	res := &ulvp.ChainHeaderProofMsg{
		Proof:  proof,
		Header: heads,
		Right:  Right,
	}
	return res.Datas()
}

func (uv *SimpleULVP) VerifyFirstMsg(data []byte) error {
	msg, err := ParseProofMsg(data)
	if err != nil {
		return err
	}

	if len(msg.Header) == 1 && msg.Header[0].Number.Uint64() == 0 {
		return nil
	}

	if pBlocks, err := ulvp.VerifyRequiredBlocks(msg.Proof, msg.Right); err != nil {
		return err
	} else {
		if !msg.Proof.VerifyProof(pBlocks) {
			return errors.New("Verify Proof Failed on first msg")
		}
	}
	return nil
}

func (uv *SimpleULVP) GetSimpleUlvpMsgReq(blocks []uint64) *ulvp.UlvpMsgReq {
	return makeUlvpMsgReq(blocks)
}

func (uv *SimpleULVP) HandleSimpleUlvpMsgReq(msg *ulvp.UlvpMsgReq) (*ulvp.UlvpMsgRes, error) {

	return uv.tryHandleSimpleUlvpMsgReq(msg)
}
func (uv *SimpleULVP) tryHandleSimpleUlvpMsgReq(msg *ulvp.UlvpMsgReq) (*ulvp.UlvpMsgRes, error) { 
	res := ulvp.NewUlvpMsgRes()
	// generate proof the leatest localChain
	cur1 := uv.localChain.CurrentBlock()
	curNum1 := cur1.NumberU64()
	genesis := uv.localChain.GetBlockByNumber(0)
	MmrInfo,root := uv.getTailMmr()

	cur := uv.localChain.GetBlockByHash(root)
	if cur == nil {
		return nil,fmt.Errorf("not happend,hash:%v,height:%v",hex.EncodeToString(root[:]),curNum1)
	}
	curNum := cur.NumberU64()

	Right, heads := getRightDifficult(uv.localChain, curNum, big.NewInt(0))
	proof, _, _ := MmrInfo.CreateNewProof(Right)
	// heads[0]=genesis,heads[1]=confirmHeade and leatest header
	heads = append([]*types.Header{genesis.Header()}, heads...)
	res.FirstRes.Proof, res.FirstRes.Header = proof, heads
	res.FirstRes.Right = new(big.Int).Set(Right)

	// handle next req
	blocks := msg.SecondReq.Check
	sort.Slice(blocks, func(i, j int) bool {
		return blocks[i] < blocks[j]
	})
	if blocks[len(blocks)-1] > curNum + 1 {
		return nil, errors.New("the proof point over the leatest localChain height")
	}
	// blocks = append(blocks, curNum)
	// will send the block head with proofs to peer
	if b := uv.localChain.GetBlockByNumber(blocks[0]); b != nil {
		proof2 := MmrInfo.GenerateProof2(blocks[0], curNum)
		res.SecondRes.Proof = proof2
		res.SecondRes.Header = []*types.Header{b.Header()}
	} else {
		return nil, fmt.Errorf("cann't found the block: %v", blocks[0])
	}

	return res, nil
}


func (uv *SimpleULVP) MakeUvlpChainProof(msg *ulvp.UlvpMsgRes) *ulvp.UlvpChainProof {
	return &ulvp.UlvpChainProof{
		Remote: uv.RemoteChain.Copy(),
		Res:    msg,
	}
}

func (uv *SimpleULVP) GetReceiptProof(txHash common.Hash) (*ulvp.ReceiptTrieResps, *types.Receipt, error) {

	lookup := uv.localChain.GetTransactionLookup(txHash)
	if uv.localChain.GetCanonicalHash(lookup.BlockIndex) != lookup.BlockHash {
		return nil, nil, errors.New("hash is not currently canonical")
	}
	block := uv.localChain.GetBlockByHash(lookup.BlockHash)

	receipts := uv.localChain.GetReceiptsByHash(lookup.BlockHash)
	var receipt *types.Receipt
	for _, v := range receipts {
		if v.TxHash == txHash {
			receipt = v
		}
	}

	tri := types.DeriveShaHasher(receipts, new(trie.Trie))
	keybuf := new(bytes.Buffer)
	keybuf.Reset()
	rlp.Encode(keybuf, lookup.Index)
	proofs := types.NewNodeSet()

	tri.Prove(keybuf.Bytes(), 0, proofs)

	return &ulvp.ReceiptTrieResps{Proofs: proofs.NodeList(), Index: lookup.Index, ReceiptHash: block.ReceiptHash()}, receipt, nil
}

func (uv *SimpleULVP) VerifyReceiptProof(receiptPes *ulvp.ReceiptTrieResps) (receipt *types.Receipt, err error) {
	keybuf := new(bytes.Buffer)
	keybuf.Reset()
	rlp.Encode(keybuf, receiptPes.Index)
	value, err := trie.VerifyProof(receiptPes.ReceiptHash, keybuf.Bytes(), receiptPes.Proofs.NodeSet())
	if err := rlp.DecodeBytes(value, receipt); err != nil {
		return nil, err
	}
	return receipt, err
}
func (uv *SimpleULVP) getTailMmr() (*ulvp.Mmr,common.Hash) {
	mmr := uv.MmrInfo.Copy()
	n := mmr.Pop2()

	return mmr,n.GetHash()
}
///////////////////////////////////////////////////////////////////////////////////
