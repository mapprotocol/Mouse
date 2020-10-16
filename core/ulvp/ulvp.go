package ulvp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/marcopoloprotoco/mouse/common"
	"github.com/marcopoloprotoco/mouse/core/types"
	"github.com/marcopoloprotoco/mouse/rlp"
	"github.com/marcopoloprotoco/mouse/trie"
	"math/big"
)

type BaseReqUlvpMsg struct {
	Check []uint64
	Right *big.Int
}

func (b *BaseReqUlvpMsg) Datas() ([]byte, error) {
	data, err := rlp.EncodeToBytes(b)
	if err != nil {
		return nil, err
	}
	return data, nil
}

type UlvpMsgReq struct {
	FirstReq  *BaseReqUlvpMsg
	SecondReq *BaseReqUlvpMsg
}

func (b *UlvpMsgReq) Datas() ([]byte, error) {
	data, err := rlp.EncodeToBytes(b)
	if err != nil {
		return nil, err
	}
	return data, nil
}

type ChainHeaderProofMsg struct {
	Proof  *ProofInfo // the leatest blockchain and an proof of existence
	Header []*types.Header
	Right  *big.Int
}

func newChainHeaderProofMsg() *ChainHeaderProofMsg {
	return &ChainHeaderProofMsg{
		Proof:  &ProofInfo{},
		Header: []*types.Header{},
		Right:  big.NewInt(0),
	}
}
func (b *ChainHeaderProofMsg) Datas() ([]byte, error) {
	data, err := rlp.EncodeToBytes(b)
	if err != nil {
		return nil, err
	}
	return data, nil
}

type ChainInProofMsg struct {
	Proof  *ProofInfo
	Header []*types.Header
}

func newChainInProofMsg() *ChainInProofMsg {
	return &ChainInProofMsg{
		Proof:  &ProofInfo{},
		Header: []*types.Header{},
	}
}

type UlvpMsgRes struct {
	FirstRes  *ChainHeaderProofMsg
	SecondRes *ChainInProofMsg
}

func NewUlvpMsgRes() *UlvpMsgRes {
	return &UlvpMsgRes{
		FirstRes:  newChainHeaderProofMsg(),
		SecondRes: newChainInProofMsg(),
	}
}

func (b *UlvpMsgRes) Datas() ([]byte, error) {
	data, err := rlp.EncodeToBytes(b)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func (b *UlvpMsgRes) checkMmrRoot() error {
	if b.FirstRes != nil && b.SecondRes != nil {
		fRoot,sRoot := b.FirstRes.Proof.RootHash, b.SecondRes.Proof.RootHash
		if !bytes.Equal(fRoot[:], sRoot[:]) {
			fmt.Println("mmr root not match for second proof,first:", hex.EncodeToString(fRoot[:]), "second:", hex.EncodeToString(sRoot[:]))
			return errors.New("mmr root not match for second proof")
		}
		return nil
	}
	return errors.New("invalid params in checkMmrRoot")
}
///////////////////////////////////////////////////////////////////////////////////

type OtherChainAdapter struct {
	Genesis      common.Hash
	ConfirmBlock *types.Header
	ProofHeader  *types.Header
	Leatest      []*types.Header
}

func (o *OtherChainAdapter) Copy() *OtherChainAdapter {
	tmp := &OtherChainAdapter{
		Genesis:      o.Genesis,
		ConfirmBlock: &types.Header{},
		ProofHeader:  &types.Header{},
		Leatest:      o.Leatest,
	}
	if o.ConfirmBlock != nil {
		tmp.ConfirmBlock = types.CopyHeader(o.ConfirmBlock)
	}
	if o.ProofHeader != nil {
		tmp.ProofHeader = types.CopyHeader(o.ProofHeader)
	}
	fmt.Println("***Genesis***",hex.EncodeToString(tmp.Genesis[:]))
	return tmp
}

// header block check
func (o *OtherChainAdapter) originHeaderCheck(head []*types.Header) error {
	// check difficult
	return nil
}

func (o *OtherChainAdapter) GenesisCheck(head *types.Header) error {
	
	rHash, lHash := head.Hash(), o.Genesis
	if !bytes.Equal(rHash[:], lHash[:]) {
		fmt.Println("genesis not match,local:", hex.EncodeToString(lHash[:]), "remote:", hex.EncodeToString(rHash[:]))
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
func (o *OtherChainAdapter) checkMmrRootForFirst(root common.Hash) error {
	if len(o.Leatest) > 0 {
		l := o.Leatest[len(o.Leatest) - 1]
		rHash := l.MmrRoot
		if !bytes.Equal(root[:], rHash[:]) {
			fmt.Println("mmr root not match for first proof in header:", hex.EncodeToString(root[:]), "root in proof:", hex.EncodeToString(rHash[:]))
			return errors.New("genesis not match")
		}
		return nil
	}
	return errors.New("not get the first proof")
}

///////////////////////////////////////////////////////////////////////////////////

type UlvpChainProof struct {
	Remote *OtherChainAdapter   		`json:"remote"     rlp:"nil"`
	Res    *UlvpMsgRes
}

func (uc *UlvpChainProof) Verify() error {

	if pBlocks, err := VerifyRequiredBlocks(uc.Res.FirstRes.Proof, uc.Res.FirstRes.Right); err != nil {
		return err
	} else {
		if !uc.Res.FirstRes.Proof.VerifyProof(pBlocks) {
			return errors.New("Verify Proof Failed on first msg")
		} else {
			if err := uc.Remote.GenesisCheck(uc.Res.FirstRes.Header[0]); err != nil {
				return err
			}
			if err := uc.Remote.checkAndSetHeaders(uc.Res.FirstRes.Header, false); err != nil {
				return err
			}
			if err := uc.Remote.checkMmrRootForFirst(uc.Res.FirstRes.Proof.RootHash); err != nil {
				return err
			}
			if pBlocks, err := VerifyRequiredBlocks2(uc.Res.SecondRes.Proof); err != nil {
				return err
			} else {
				if !uc.Res.SecondRes.Proof.VerifyProof2(pBlocks) {
					return errors.New("Verify Proof2 Failed on first msg")
				}
				if err := uc.checkMmrRoot(); err != nil {
					return err
				}
				// check headers
				return uc.Remote.checkAndSetHeaders(uc.Res.SecondRes.Header, true)
			}
		}
	}
	return nil
}
func (uc *UlvpChainProof) checkMmrRoot() error {
	return uc.Res.checkMmrRoot() 
}

type ReceiptTrieResps struct { // describes all responses, not just a single one
	Proofs      types.NodeList
	Index       uint64
	ReceiptHash common.Hash
}

func (r *ReceiptTrieResps) Verify() (*types.Receipt, error) {
	keybuf := new(bytes.Buffer)
	keybuf.Reset()
	rlp.Encode(keybuf, r.Index)
	value, err := trie.VerifyProof(r.ReceiptHash, keybuf.Bytes(), r.Proofs.NodeSet())
	if err != nil {
		return nil, err
	}

	var receipt *types.Receipt
	if err := rlp.DecodeBytes(value, &receipt); err != nil {
		return nil, err
	}

	return receipt, err
}

// newBlockData is the network packet for the block propagation message.
type SimpleUlvpProof struct {
	ChainProof   *UlvpChainProof
	ReceiptProof *ReceiptTrieResps
	End          *big.Int
	Header       *types.Header
	Result       bool
	TxHash       common.Hash
}

// UlvpTransaction is the network packet for the block propagation message.
type UlvpTransaction struct {
	SimpUlvpP *SimpleUlvpProof
	Tx        *types.Transaction
}

func (mr *SimpleUlvpProof) VerifyULVPTXMsg(txHash common.Hash) (*types.Receipt, error) {
	if !mr.Result {
		return nil, errors.New("no proof return")
	}
	if err := mr.ChainProof.Verify(); err != nil {
		return nil, err
	}

	if mr.ChainProof.Remote.ProofHeader.Number.Uint64() != mr.Header.Number.Uint64() {
		return nil, errors.New("mmr proof not match receipt proof")
	}
	receipt, err := mr.ReceiptProof.Verify()
	if err != nil {
		return nil, err
	}

	//if !reflect.DeepEqual(receipt.Bloom, mr.ReceiptProof.Receipt.Bloom) {
	//	return nil, errors.New("receipt Bloom proof not match receipt")
	//}
	//
	//if !reflect.DeepEqual(receipt.Logs, mr.ReceiptProof.Receipt.Logs) {
	//	return nil, errors.New("receipt Logs proof not match receipt")
	//}
	//
	//if !reflect.DeepEqual(receipt.CumulativeGasUsed, mr.ReceiptProof.Receipt.CumulativeGasUsed) {
	//	return nil, errors.New("receipt Logs proof not match receipt")
	//}

	if mr.TxHash != txHash {
		return nil, errors.New("txHash checkout failed")
	}
	return receipt, nil
}

func UlvpVerify(proof []byte, txHash common.Hash) error {
	su := &SimpleUlvpProof{}
	if err := rlp.DecodeBytes(proof, su); err != nil {
		return err
	}
	_, err := su.VerifyULVPTXMsg(txHash)
	return err
}
