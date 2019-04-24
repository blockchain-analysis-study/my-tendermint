package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"my-tendermint/tendermint/crypto"
	cmn "my-tendermint/tendermint/libs/common"
	tmtime "my-tendermint/tendermint/types/time"
)

const (
	// MaxChainIDLen is a maximum length of the chain ID.
	MaxChainIDLen = 50
)

//------------------------------------------------------------
// core types for a genesis definition
// NOTE: any changes to the genesis definition should
// be reflected in the documentation:
// docs/tendermint-core/using-tendermint.md
/**
TODO 超级重要

创世定义的核心类型
注意：对起源定义的任何更改都应反映在文档中：
文档/ tendermint核/ using-tendermint.md
 */

// GenesisValidator is an initial validator.
// GenesisValidator是一个初始验证器
type GenesisValidator struct {
	// 验证人地址
	Address Address       `json:"address"`
	// 验证人公钥
	PubKey  crypto.PubKey `json:"pub_key"`
	// 得票权重值
	Power   int64         `json:"power"`
	// 验证人名称
	Name    string        `json:"name"`
}

// GenesisDoc defines the initial conditions for a tendermint blockchain, in particular its validator set.
// GenesisDoc定义了一个tendermint区块链的初始条件，特别是它的验证人集。
// 定义了tendermint 网络的创世文件
type GenesisDoc struct {
	// 创世块的时间戳
	GenesisTime     time.Time          `json:"genesis_time"`
	// 链ID
	ChainID         string             `json:"chain_id"`
	// 共识参数
	ConsensusParams *ConsensusParams   `json:"consensus_params,omitempty"`
	// 创世轮内置的验证人
	Validators      []GenesisValidator `json:"validators,omitempty"`
	AppHash         cmn.HexBytes       `json:"app_hash"`
	AppState        json.RawMessage    `json:"app_state,omitempty"`
}

// SaveAs is a utility method for saving GenensisDoc as a JSON file.
func (genDoc *GenesisDoc) SaveAs(file string) error {
	genDocBytes, err := cdc.MarshalJSONIndent(genDoc, "", "  ")
	if err != nil {
		return err
	}
	return cmn.WriteFile(file, genDocBytes, 0644)
}

// ValidatorHash returns the hash of the validator set contained in the GenesisDoc
func (genDoc *GenesisDoc) ValidatorHash() []byte {
	vals := make([]*Validator, len(genDoc.Validators))
	for i, v := range genDoc.Validators {
		vals[i] = NewValidator(v.PubKey, v.Power)
	}
	vset := NewValidatorSet(vals)
	return vset.Hash()
}

// ValidateAndComplete checks that all necessary fields are present
// and fills in defaults for optional fields left empty
/**
ValidateAndComplete:
检查是否存在所有必需字段，并填写左侧为可选字段的默认值
 */
func (genDoc *GenesisDoc) ValidateAndComplete() error {
	if genDoc.ChainID == "" {
		return cmn.NewError("Genesis doc must include non-empty chain_id")
	}
	if len(genDoc.ChainID) > MaxChainIDLen {
		return cmn.NewError("chain_id in genesis doc is too long (max: %d)", MaxChainIDLen)
	}

	if genDoc.ConsensusParams == nil {
		genDoc.ConsensusParams = DefaultConsensusParams()
	} else {
		if err := genDoc.ConsensusParams.Validate(); err != nil {
			return err
		}
	}

	for i, v := range genDoc.Validators {
		if v.Power == 0 {
			return cmn.NewError("The genesis file cannot contain validators with no voting power: %v", v)
		}
		if len(v.Address) > 0 && !bytes.Equal(v.PubKey.Address(), v.Address) {
			return cmn.NewError("Incorrect address for validator %v in the genesis file, should be %v", v, v.PubKey.Address())
		}
		if len(v.Address) == 0 {
			genDoc.Validators[i].Address = v.PubKey.Address()
		}
	}

	if genDoc.GenesisTime.IsZero() {
		genDoc.GenesisTime = tmtime.Now()
	}

	return nil
}

//------------------------------------------------------------
// Make genesis state from file

// GenesisDocFromJSON unmarshalls JSON data into a GenesisDoc.
func GenesisDocFromJSON(jsonBlob []byte) (*GenesisDoc, error) {
	genDoc := GenesisDoc{}
	err := cdc.UnmarshalJSON(jsonBlob, &genDoc)
	if err != nil {
		return nil, err
	}

	if err := genDoc.ValidateAndComplete(); err != nil {
		return nil, err
	}

	return &genDoc, err
}

// GenesisDocFromFile reads JSON data from a file and unmarshalls it into a GenesisDoc.
func GenesisDocFromFile(genDocFile string) (*GenesisDoc, error) {
	jsonBlob, err := ioutil.ReadFile(genDocFile)
	if err != nil {
		return nil, cmn.ErrorWrap(err, "Couldn't read GenesisDoc file")
	}
	genDoc, err := GenesisDocFromJSON(jsonBlob)
	if err != nil {
		return nil, cmn.ErrorWrap(err, fmt.Sprintf("Error reading GenesisDoc at %v", genDocFile))
	}
	return genDoc, nil
}
