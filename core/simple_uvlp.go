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
	"github.com/marcopoloprotoco/mouse/rlp"
	// "golang.org/x/crypto/sha3"
)

var (
	K = 6
)

type BaseReqUvlpMsg struct {
	Check []uint64
	Right *big.Int
}

func (b *BaseReqUvlpMsg) Datas() ([]byte, error) {
	data, err := rlp.EncodeToBytes(b)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func (b *BaseReqUvlpMsg) Parse(data []byte) error {
	obj := &BaseReqUvlpMsg{}
	err := rlp.DecodeBytes(data, obj)
	if err != nil {
		b = obj
	}
	return err
}
func makeFirstBaseUvlopMsg() *BaseReqUvlpMsg {
	return &BaseReqUvlpMsg{
		Check: []uint64{0},
		Right: big.NewInt(0),
	}
}

type UvlpMsgReq struct {
	FirstReq  *BaseReqUvlpMsg
	SecondReq *BaseReqUvlpMsg
}

func (b *UvlpMsgReq) Datas() ([]byte, error) {
	data, err := rlp.EncodeToBytes(b)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func (b *UvlpMsgReq) Parse(data []byte) error {
	obj := &UvlpMsgReq{}
	err := rlp.DecodeBytes(data, obj)
	if err != nil {
		b = obj
	}
	return err
}
func makeUvlpMsgReq(blocks []uint64) *UvlpMsgReq {
	return &UvlpMsgReq{
		FirstReq: makeFirstBaseUvlopMsg(),
		SecondReq: &BaseReqUvlpMsg{
			Check: blocks,
		},
	}
}

type ChainHeaderProofMsg struct {
	Proof  *ProofInfo // the leatest blockchain and an proof of existence
	Header []*types.Header
	Right  *big.Int
}

func (b *ChainHeaderProofMsg) Datas() ([]byte, error) {
	data, err := rlp.EncodeToBytes(b)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func (b *ChainHeaderProofMsg) Parse(data []byte) error {
	obj := &ChainHeaderProofMsg{}
	err := rlp.DecodeBytes(data, obj)
	if err != nil {
		b = obj
	}
	return err
}

type ChainInProofMsg struct {
	Proof  *ProofInfo
	Header []*types.Header
}

type UvlpMsgRes struct {
	FirstRes  *ChainHeaderProofMsg
	SecondRes *ChainInProofMsg
}

func (b *UvlpMsgRes) Datas() ([]byte, error) {
	data, err := rlp.EncodeToBytes(b)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func (b *UvlpMsgRes) Parse(data []byte) error {
	obj := &UvlpMsgRes{}
	err := rlp.DecodeBytes(data, obj)
	if err != nil {
		b = obj
	}
	return err
}

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

///////////////////////////////////////////////////////////////////////////////////

type OtherChainAdapter struct {
	Genesis      *types.Block
	ConfirmBlock *types.Header
	ProofHeader  *types.Header
	ProofHeight  uint64
	Leatest      []*types.Header
}

// header block check
func (o *OtherChainAdapter) originHeaderCheck(head []*types.Header) error {
	// check difficult
	return nil
}
func (o *OtherChainAdapter) setProofHeight(h uint64) {
	o.ProofHeight = h
}
func (o *OtherChainAdapter) GenesisCheck(head *types.Header) error {
	rHash, lHash := head.Hash(), o.Genesis.Header().Hash()
	if !bytes.Equal(rHash[:], lHash[:]) {
		fmt.Println("genesis not match,loack:", hex.EncodeToString(lHash[:]), "remote:", hex.EncodeToString(rHash[:]))
		return errors.New("genesis not match")
	}
	return nil
}

func (o *OtherChainAdapter) checkAndSetHeaders(heads []*types.Header, setcur bool) error {
	if len(heads) == 0 {
		return errors.New("invalid params")
	}
	
	if err := o.originHeaderCheck(heads); err != nil {
		return err
	}

	if setcur {
		head := heads[0]
		if head.Number.Uint64() != o.ProofHeight {
			fmt.Println("height not match,l:", o.ProofHeight, "r:", head.Number)
			return errors.New("height not match")
		}
		o.setProofHeader(head)
	} else {
		o.setLeatestHeader(heads[1], heads[2:])
	}
	return nil
}
func (o *OtherChainAdapter) setProofHeader(head *types.Header) {
	o.ProofHeader = types.CopyHeader(head)
}
func (o *OtherChainAdapter) setLeatestHeader(confirm *types.Header, leatest []*types.Header) {
	o.ConfirmBlock = types.CopyHeader(confirm)
	tmp := []*types.Header{}
	for _, v := range leatest {
		tmp = append(tmp, types.CopyHeader(v))
	}
	o.Leatest = tmp
}

///////////////////////////////////////////////////////////////////////////////////

type SimpleUVLP struct {
	MmrInfo     *Mmr
	localChain  *BlockChain
	RemoteChain *OtherChainAdapter
}

func NewSimpleUVLP() *SimpleUVLP {
	return nil
}

func (uv *SimpleUVLP) GetFirstMsg() *BaseReqUvlpMsg {
	return makeFirstBaseUvlopMsg()
}

func (uv *SimpleUVLP) PushFirstMsg() ([]byte, error) {
	cur := uv.localChain.CurrentBlock()
	curNum := cur.NumberU64()
	genesis := uv.localChain.GetBlockByNumber(0)
	Right, heads := getRightDifficult(uv.localChain, curNum, cur.Difficulty())
	proof, _, _ := uv.MmrInfo.CreateNewProof(Right)
	heads = append([]*types.Header{genesis.Header(), cur.Header()}, heads...)

	res := &ChainHeaderProofMsg{
		Proof:  proof,
		Header: heads,
		Right:  Right,
	}
	return res.Datas()
}

func (uv *SimpleUVLP) VerifyFirstMsg(data []byte) error {
	msg := &ChainHeaderProofMsg{}
	if err := msg.Parse(data); err != nil {
		return err
	}

	if pBlocks, err := VerifyRequiredBlocks(msg.Proof, msg.Right); err != nil {
		return err
	} else {
		if !msg.Proof.VerifyProof(pBlocks) {
			return errors.New("Verify Proof Failed on first msg")
		}
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////
func (uv *SimpleUVLP) GetSimpleUvlpMsgReq(blocks []uint64) *UvlpMsgReq {
	uv.RemoteChain.setProofHeight(blocks[0])
	return makeUvlpMsgReq(blocks)
}

func (uv *SimpleUVLP) HandleSimpleUvlpMsgReq(msg *UvlpMsgReq) (*UvlpMsgRes, error) {
	res := &UvlpMsgRes{}
	// generate proof the leatest localChain
	cur := uv.localChain.CurrentBlock()
	genesis := uv.localChain.GetBlockByNumber(0)
	curNum := cur.NumberU64()
	Right, heads := getRightDifficult(uv.localChain, curNum, cur.Difficulty())
	proof, _, _ := uv.MmrInfo.CreateNewProof(Right)
	// heads[0]=genesis,heads[1]=confirmHeade and leatest header
	heads = append([]*types.Header{genesis.Header()}, heads...)
	res.FirstRes.Proof, res.FirstRes.Header = proof, heads
	res.FirstRes.Right = new(big.Int).Set(Right)

	// handle next req
	blocks := msg.SecondReq.Check
	sort.Slice(blocks, func(i, j int) bool {
		return blocks[i] < blocks[j]
	})
	if blocks[len(blocks)-1] > curNum {
		return nil, errors.New("the proof point over the leatest localChain height")
	}
	// blocks = append(blocks, curNum)
	// will send the block head with proofs to peer
	if b := uv.localChain.GetBlockByNumber(blocks[0]); b != nil {
		proof2 := uv.MmrInfo.GenerateProof(blocks[0], curNum)
		res.SecondRes.Proof = proof2
		res.SecondRes.Header = []*types.Header{b.Header()}
	} else {
		return nil, fmt.Errorf("cann't found the block: %v", blocks[0])
	}

	return res, nil
}

func (uv *SimpleUVLP) VerfiySimpleUvlpMsg(msg *UvlpMsgRes, secondBlocks []uint64) error {
	if pBlocks, err := VerifyRequiredBlocks(msg.FirstRes.Proof, msg.FirstRes.Right); err != nil {
		return err
	} else {
		if !msg.FirstRes.Proof.VerifyProof(pBlocks) {
			return errors.New("Verify Proof Failed on first msg")
		} else {
			if err := uv.RemoteChain.GenesisCheck(msg.FirstRes.Header[0]); err != nil {
				return err
			}
			if err := uv.RemoteChain.checkAndSetHeaders(msg.FirstRes.Header, false); err != nil {
				return err
			}
			// verify proof2
			if secondBlocks != nil {
				if !Uint64SliceEqual(secondBlocks, msg.SecondRes.Proof.Checked) {
					return fmt.Errorf("blocks not match,local:%v,remote:%v", secondBlocks, msg.SecondRes.Proof.Checked)
				}
			}
			if pBlocks, err := VerifyRequiredBlocks2(msg.SecondRes.Proof); err != nil {
				return err
			} else {
				if !msg.SecondRes.Proof.VerifyProof2(pBlocks) {
					return errors.New("Verify Proof2 Failed on first msg")
				}
				// check headers
				return uv.RemoteChain.checkAndSetHeaders(msg.SecondRes.Header, true)
			}
		}
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////

func getRightDifficult(localChain *BlockChain, curNum uint64, r *big.Int) (*big.Int, []*types.Header) {
	heads := []*types.Header{}
	i := int(curNum - uint64(K))
	if i < 0 {
		i = 0
	}

	right := new(big.Int).Set(r)
	for ; i < int(K); i++ {
		b := localChain.GetBlockByNumber(uint64(i))
		if b != nil {
			heads = append(heads, b.Header())
			right = new(big.Int).Add(right, b.Difficulty())
		}
	}
	return right, heads
}

type ReceiptTrieResps struct { // describes all responses, not just a single one
	Proofs      types.NodeList
	Index       uint64
	ReceiptHash common.Hash
	Receipt     *types.Receipt
}

// newBlockData is the network packet for the block propagation message.
type MMRReceiptProof struct {
	MMRProof     *UvlpMsgRes
	ReceiptProof *ReceiptTrieResps
	End          *big.Int
	Header       *types.Header
	Result       bool
}

func (uv *SimpleUVLP) GetReceiptProof(txHash common.Hash) (*ReceiptTrieResps, error) {

	lookup := uv.localChain.GetTransactionLookup(txHash)
	if uv.localChain.GetCanonicalHash(lookup.BlockIndex) != lookup.BlockHash {
		return nil, errors.New("hash is not currently canonical")
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

	return &ReceiptTrieResps{Proofs: proofs.NodeList(), Index: lookup.Index, ReceiptHash: block.ReceiptHash(), Receipt: receipt}, nil
}

func (uv *SimpleUVLP) VerifyReceiptProof(receiptPes *ReceiptTrieResps) (value []byte, err error) {
	keybuf := new(bytes.Buffer)
	keybuf.Reset()
	rlp.Encode(keybuf, receiptPes.Index)
	value, err = trie.VerifyProof(receiptPes.ReceiptHash, keybuf.Bytes(), receiptPes.Proofs.NodeSet())
	return value, err
}

func (uv *SimpleUVLP) VerifyULVPTXMsg(mr *MMRReceiptProof) error {
	if !mr.Result {
		return errors.New("no proof return")
	}
	err := uv.VerfiySimpleUvlpMsg(mr.MMRProof, nil)
	if err != nil {
		return err
	}
	if uv.RemoteChain.ProofHeader != mr.Header {
		return errors.New("mmr proof not match receipt proof")
	}
	_, err = uv.VerifyReceiptProof(mr.ReceiptProof)
	if err != nil {
		return err
	}
	return nil
}
