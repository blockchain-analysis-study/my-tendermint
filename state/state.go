package state

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"time"

	"my-tendermint/tendermint/types"
	tmtime "my-tendermint/tendermint/types/time"
	"my-tendermint/tendermint/version"
)

// database keys
var (

	/**
	TODO state 的key  这个和 keystore 中的 不一样哦！看 keystore中那个 state 的描述
	 */
	stateKey = []byte("stateKey")
)

//-----------------------------------------------------------------------------

// Version is for versioning the State.
// It holds the Block and App version needed for making blocks,
// and the software version to support upgrades to the format of
// the State as stored on disk.
type Version struct {
	Consensus version.Consensus
	Software  string
}

// initStateVersion sets the Consensus.Block and Software versions,
// but leaves the Consensus.App version blank.
// The Consensus.App version will be set during the Handshake, once
// we hear from the app what protocol version it is running.
var initStateVersion = Version{
	Consensus: version.Consensus{
		Block: version.BlockProtocol,
		App:   0,
	},
	Software: version.TMCoreSemVer,
}

//-----------------------------------------------------------------------------

// State is a short description of the latest committed block of the Tendermint consensus.
// It keeps all information necessary to validate new blocks,
// including the last validator set and the consensus params.
// All fields are exposed so the struct can be easily serialized,
// but none of them should be mutated directly.
// Instead, use state.Copy() or state.NextState(...).
// NOTE: not goroutine-safe.

/**
TODO 这个东西超级重要
State
 */
type State struct {
	// 版本
	Version Version

	// immutable
	// 链ID
	ChainID string

	// LastBlockHeight=0 at genesis (ie. block(H=0) does not exist)
	// 最新确认块的块高
	LastBlockHeight  int64
	// 最新确认块的 总交易数
	LastBlockTotalTx int64
	// 最新确认块的区块ID
	LastBlockID      types.BlockID
	// 最新确认块的时间戳
	LastBlockTime    time.Time

	// LastValidators is used to validate block.LastCommit.
	// Validators are persisted to the database separately every time they change,
	// so we can query for historical validator sets.
	// Note that if s.LastBlockHeight causes a valset change,
	// we set s.LastHeightValidatorsChanged = s.LastBlockHeight + 1 + 1
	// Extra +1 due to nextValSet delay.
	/**
	下一轮的验证人
	 */
	NextValidators              *types.ValidatorSet

	/**
	当前轮的验证人
	 */
	Validators                  *types.ValidatorSet
	/**
	上一轮的验证人
	 */
	LastValidators              *types.ValidatorSet
	// 最新确认块中 验证人变更个数 ？
	LastHeightValidatorsChanged int64

	// Consensus parameters used for validating blocks.
	// Changes returned by EndBlock and updated after Commit.
	/**
	用于验证块的共识参数。
	EndBlock返回的更改并在Commit之后更新。
	 */
	ConsensusParams                  types.ConsensusParams
	LastHeightConsensusParamsChanged int64

	// Merkle root of the results from executing prev block
	// Merkle root的结果来自执行prev块
	LastResultsHash []byte

	// the latest AppHash we've received from calling abci.Commit()
	// 我们从调用abci.Commit（）收到的最新AppHash
	AppHash []byte
}

// Copy makes a copy of the State for mutating.
// Copy 状态
func (state State) Copy() State {
	return State{
		Version: state.Version,
		ChainID: state.ChainID,

		LastBlockHeight:  state.LastBlockHeight,
		LastBlockTotalTx: state.LastBlockTotalTx,
		LastBlockID:      state.LastBlockID,
		LastBlockTime:    state.LastBlockTime,

		NextValidators:              state.NextValidators.Copy(),
		Validators:                  state.Validators.Copy(),
		LastValidators:              state.LastValidators.Copy(),
		LastHeightValidatorsChanged: state.LastHeightValidatorsChanged,

		ConsensusParams:                  state.ConsensusParams,
		LastHeightConsensusParamsChanged: state.LastHeightConsensusParamsChanged,

		AppHash: state.AppHash,

		LastResultsHash: state.LastResultsHash,
	}
}

// Equals returns true if the States are identical.
func (state State) Equals(state2 State) bool {
	sbz, s2bz := state.Bytes(), state2.Bytes()
	return bytes.Equal(sbz, s2bz)
}

// Bytes serializes the State using go-amino.
func (state State) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(state)
}

// IsEmpty returns true if the State is equal to the empty State.
func (state State) IsEmpty() bool {
	return state.Validators == nil // XXX can't compare to Empty
}

//------------------------------------------------------------------------
// Create a block from the latest state

// MakeBlock builds a block from the current state with the given txs, commit,
// and evidence. Note it also takes a proposerAddress because the state does not
// track rounds, and hence does not know the correct proposer. TODO: fix this!
/**
从最新状态创建一个块.

MakeBlock:
使用给定的txs, commit和evidence从当前状态构建一个块。
注意它也需要一个proposerAddress，因为状态不跟踪轮次，因此不知道正确的提议者。 TODO：解决这个问题！
【注意】 也就是说，目前 cosmos 中只保存最新的状态和 block信息
 */
func (state State) MakeBlock(
	// 当前块高
	height int64,
	// 块中的所有 tx
	txs []types.Tx,
	// 一个 commit 信息
	commit *types.Commit,

	// 一些 凭证集合
	evidence []types.Evidence,

	// 当前区块的提议者 地址(出块者地址)
	proposerAddress []byte,
) (*types.Block, *types.PartSet) {

	// Build base block with block data.
	// 创建一个具备基础信息的block
	block := types.MakeBlock(height, txs, commit, evidence)

	// Set time.
	// 设置出块时间
	var timestamp time.Time
	if height == 1 {
		timestamp = state.LastBlockTime // genesis time
	} else {
		timestamp = MedianTime(commit, state.LastValidators)
	}

	// Fill rest of header with state data.
	/**
	用状态数据填充剩余的 header 字段。
	 */
	block.Header.Populate(
		state.Version.Consensus, state.ChainID,
		timestamp, state.LastBlockID, state.LastBlockTotalTx+block.NumTxs,
		state.Validators.Hash(), state.NextValidators.Hash(),
		state.ConsensusParams.Hash(), state.AppHash, state.LastResultsHash,
		proposerAddress,
	)

	return block, block.MakePartSet(types.BlockPartSizeBytes)
}

// MedianTime computes a median time for a given Commit (based on Timestamp field of votes messages) and the
// corresponding validator set. The computed time is always between timestamps of
// the votes sent by honest processes, i.e., a faulty processes can not arbitrarily increase or decrease the
// computed value.
func MedianTime(commit *types.Commit, validators *types.ValidatorSet) time.Time {

	weightedTimes := make([]*tmtime.WeightedTime, len(commit.Precommits))
	totalVotingPower := int64(0)

	for i, vote := range commit.Precommits {
		if vote != nil {
			_, validator := validators.GetByIndex(vote.ValidatorIndex)
			totalVotingPower += validator.VotingPower
			weightedTimes[i] = tmtime.NewWeightedTime(vote.Timestamp, validator.VotingPower)
		}
	}

	return tmtime.WeightedMedian(weightedTimes, totalVotingPower)
}

//------------------------------------------------------------------------
// Genesis

// MakeGenesisStateFromFile reads and unmarshals state from the given
// file.
//
// Used during replay and in tests.
func MakeGenesisStateFromFile(genDocFile string) (State, error) {
	genDoc, err := MakeGenesisDocFromFile(genDocFile)
	if err != nil {
		return State{}, err
	}
	return MakeGenesisState(genDoc)
}

// MakeGenesisDocFromFile reads and unmarshals genesis doc from the given file.
func MakeGenesisDocFromFile(genDocFile string) (*types.GenesisDoc, error) {
	genDocJSON, err := ioutil.ReadFile(genDocFile)
	if err != nil {
		return nil, fmt.Errorf("Couldn't read GenesisDoc file: %v", err)
	}
	genDoc, err := types.GenesisDocFromJSON(genDocJSON)
	if err != nil {
		return nil, fmt.Errorf("Error reading GenesisDoc: %v", err)
	}
	return genDoc, nil
}

// MakeGenesisState creates state from types.GenesisDoc.
func MakeGenesisState(genDoc *types.GenesisDoc) (State, error) {
	err := genDoc.ValidateAndComplete()
	if err != nil {
		return State{}, fmt.Errorf("Error in genesis file: %v", err)
	}

	var validatorSet, nextValidatorSet *types.ValidatorSet
	if genDoc.Validators == nil {
		validatorSet = types.NewValidatorSet(nil)
		nextValidatorSet = types.NewValidatorSet(nil)
	} else {

		/**
		加载 创世文件中的验证人信息
		 */
		validators := make([]*types.Validator, len(genDoc.Validators))
		for i, val := range genDoc.Validators {
			validators[i] = types.NewValidator(val.PubKey, val.Power)
		}
		/**
		加载 创世文件中的验证人信息
		*/
		validatorSet = types.NewValidatorSet(validators)
		// copy当前轮的形成下一轮？
		nextValidatorSet = types.NewValidatorSet(validators).CopyIncrementProposerPriority(1)
	}

	return State{
		Version: initStateVersion,
		ChainID: genDoc.ChainID,

		LastBlockHeight: 0,
		LastBlockID:     types.BlockID{},
		LastBlockTime:   genDoc.GenesisTime,

		NextValidators:              nextValidatorSet,
		Validators:                  validatorSet,
		LastValidators:              types.NewValidatorSet(nil),
		LastHeightValidatorsChanged: 1,

		ConsensusParams:                  *genDoc.ConsensusParams,
		LastHeightConsensusParamsChanged: 1,

		AppHash: genDoc.AppHash,
	}, nil
}
