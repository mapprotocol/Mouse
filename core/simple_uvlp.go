package core

import (
	// "bytes"
	// "fmt"
	"sort"
	"errors"
	"math/big"
	// "github.com/marcopoloprotoco/mouse/common"
	"github.com/marcopoloprotoco/mouse/rlp"
	"github.com/marcopoloprotoco/mouse/core/types"
	// "golang.org/x/crypto/sha3"
)

type BaseUvlpMsg struct {
	Check 	[]uint64
	Right	*big.Int	
}

func (b *BaseUvlpMsg) Datas() ([]byte,error) {
	data, err := rlp.EncodeToBytes(b)
	if err != nil {
		return nil,err
	}
	return data,nil
}
func (b *BaseUvlpMsg) Parse(data []byte) error {
	obj := &BaseUvlpMsg{}
	err := rlp.DecodeBytes(data,obj)
	if err != nil {
		b = obj
	}
	return err
}
func makeFirstBaseUvlopMsg() *BaseUvlpMsg {
	return &BaseUvlpMsg{
		Check: 		[]uint64{0},
		Right:		big.NewInt(0),
	}
}
func makeSecondMsg(txInBlock,leatest uint64) *BaseUvlpMsg {
	return &BaseUvlpMsg{
		Check: 		[]uint64{txInBlock,leatest},
		Right:		big.NewInt(0),
	}
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
func Uint64SliceHas(origin,sub []uint64) bool {
	for _,v := range sub {
		found := false
		for _,v2 := range origin {
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

type SimpleUVLP struct {
	MmrInfo 		*Mmr
	OtherGenesis 	*types.Block
	chain 			*BlockChain
}

func NewSimpleUVLP() *SimpleUVLP {
	return nil
}

func (uv *SimpleUVLP) GetFirstMsg() ([]byte,error) {
	return makeFirstBaseUvlopMsg().Datas()
} 

func (uv *SimpleUVLP) RecvFirstMsg(data []byte) ([]byte,error) {
	msg := &BaseUvlpMsg{}
	if err := msg.Parse(data); err != nil {
		return nil,err
	}
	proof := uv.MmrInfo.GenerateProof(msg.Check)
	return ProofInfoToBytes(proof)
}

func (uv *SimpleUVLP) verifyFirstMsg(data []byte,first *BaseUvlpMsg) error {
	proof,err := ProofInfoFromBytes(data)
	if err != nil {
		return err
	}
	if pBlocks, err := VerifyRequiredBlocks(proof, first.Right); err != nil {
		return err
	} else {
		if !proof.VerifyProof(pBlocks) {
			return errors.New("Verify Proof Failed on first msg")
		}
	}
	return nil
}

// send the UVLP msg2 (make sure the tx in the block) 
func (uv *SimpleUVLP) GetSecondMsg(txInBlock,leatest uint64) ([]byte,error) {
	return makeSecondMsg(txInBlock,leatest).Datas()
}
func (uv *SimpleUVLP) RecvSecondMsg(data []byte) ([]byte,error) {
	msg := &BaseUvlpMsg{}
	if err := msg.Parse(data); err != nil {
		return nil,err
	}
	blocks := msg.Check
	sort.Slice(blocks, func(i, j int) bool {
		return blocks[i] < blocks[j]
	})
	if blocks[len(blocks)-1] > uv.chain.CurrentBlock().NumberU64() {
		return nil,errors.New("the proof point over the leatest chain height")
	}
	// will send the block head with proofs to peer
	proof := uv.MmrInfo.GenerateProof(msg.Check)
	return ProofInfoToBytes(proof)
}

func (uv *SimpleUVLP) VerifySecondMsg(data []byte,second *BaseUvlpMsg) error {
	proof,err := ProofInfoFromBytes(data)
	if err != nil {
		return err
	}
	
	if !Uint64SliceHas(proof.Checked,second.Check) {
		return errors.New("the proof not include the number in second msg") 
	}
	if pBlocks, err := VerifyRequiredBlocks(proof, second.Right); err != nil {
		return err
	} else {
		if !proof.VerifyProof(pBlocks) {
			return errors.New("Verify Proof Failed on first msg")
		}
	}
	return nil
} 

