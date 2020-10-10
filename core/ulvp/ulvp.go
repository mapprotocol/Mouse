package ulvp

import (
	"fmt"
	"encoding/hex"
	"math/big"
	"bytes"
	"errors"
	"github.com/marcopoloprotoco/mouse/common"
	"github.com/marcopoloprotoco/mouse/rlp"
	"github.com/marcopoloprotoco/mouse/trie"
	"github.com/marcopoloprotoco/mouse/core/types"
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

type UlvpMsgRes struct {
	FirstRes  *ChainHeaderProofMsg
	SecondRes *ChainInProofMsg
}

func (b *UlvpMsgRes) Datas() ([]byte, error) {
	data, err := rlp.EncodeToBytes(b)
	if err != nil {
		return nil, err
	}
	return data, nil
}

///////////////////////////////////////////////////////////////////////////////////

type OtherChainAdapter struct {
	Genesis      *types.Block
	ConfirmBlock *types.Header
	ProofHeader  *types.Header
	ProofHeight  uint64
	Leatest      []*types.Header
}

func (o *OtherChainAdapter) Copy() *OtherChainAdapter {
	return &OtherChainAdapter{
		Genesis:		o.Genesis,
		ConfirmBlock:	types.CopyHeader(o.ConfirmBlock),
		ProofHeader:	types.CopyHeader(o.ProofHeader),
		ProofHeight:	o.ProofHeight,
		Leatest:		o.Leatest,
	}
}
// header block check
func (o *OtherChainAdapter) originHeaderCheck(head []*types.Header) error {
	// check difficult
	return nil
}
func (o *OtherChainAdapter) SetProofHeight(h uint64) {
	o.ProofHeight = h
}

func (o *OtherChainAdapter) GenesisCheck(head *types.Header) error {
	return nil

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

type UlvpChainProof struct {
	Remote 			*OtherChainAdapter
	Res 			*UlvpMsgRes
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
	
			if pBlocks, err := VerifyRequiredBlocks2(uc.Res.SecondRes.Proof); err != nil {
				return err
			} else {
				if !uc.Res.SecondRes.Proof.VerifyProof2(pBlocks) {
					return errors.New("Verify Proof2 Failed on first msg")
				}
				// check headers
				return uc.Remote.checkAndSetHeaders(uc.Res.SecondRes.Header, true)
			}
		}
	}
	return nil
}

type ReceiptTrieResps struct { // describes all responses, not just a single one
	Proofs      types.NodeList
	Index       uint64
	ReceiptHash common.Hash
	Receipt     *types.Receipt
}
func (r *ReceiptTrieResps) Verify() (receipt *types.Receipt, err error) {
	keybuf := new(bytes.Buffer)
	keybuf.Reset()
	rlp.Encode(keybuf, r.Index)
	value, err := trie.VerifyProof(r.ReceiptHash, keybuf.Bytes(), r.Proofs.NodeSet())
	if err := rlp.DecodeBytes(value, receipt); err != nil {
		return nil, err
	}
	return receipt, err
	// return nil,nil
}
// newBlockData is the network packet for the block propagation message.
type SimpleUlvpProof struct {
	ChainProof    *UlvpChainProof
	ReceiptProof *ReceiptTrieResps
	End          *big.Int
	Header       *types.Header
	Result       bool
}
func (mr *SimpleUlvpProof) VerifyULVPTXMsg(txHash common.Hash) (*types.Receipt, error) {
	if !mr.Result {
		return nil, errors.New("no proof return")
	}
	if err := mr.ChainProof.Verify(); err != nil {
		return nil,err
	}
	
	if mr.ChainProof.Remote.ProofHeader != mr.Header {
		return nil, errors.New("mmr proof not match receipt proof")
	}
	receipt, err := mr.ReceiptProof.Verify()
	if err != nil {
		return nil, err
	}
	if receipt.TxHash != txHash {
		return nil, errors.New("txHash checkout failed")
	}
	return receipt, nil
}

func UlvpVerify(proof []byte,txHash common.Hash) error {
	su := &SimpleUlvpProof{}
	if err := rlp.DecodeBytes(proof, su); err != nil {
		return err
	}
	_,err := su.VerifyULVPTXMsg(txHash)
	return err
}