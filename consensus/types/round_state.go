package types

import (
	"encoding/json"
	"fmt"
	"time"

	cmn "my-tendermint/tendermint/libs/common"
	"my-tendermint/tendermint/types"
)

//-----------------------------------------------------------------------------
// RoundStepType enum type

// RoundStepType enumerates the state of the consensus state machine
type RoundStepType uint8 // These must be numeric, ordered.

// RoundStepType
/**
共识的步骤类型
【H，R】  H 为 block height； R 为 Round
TODO 注意：

在Tendermint算法中，如果遇到对同一特定区块的同意及否决信息同时超过2/3的情况，
需要启用【外部的维护机制】去核查是否存在超过1/3的验证节点伪造签名或者投出双重选票
 */
const (

	/**
	TODO 新的高度阶段 【H+1】


	步骤：
	将于提交信息转移至 【最近】(last) 的提交信息,
	并增加block height。

	结果：
	等待一定超时时间，让落后的节点 提交区块，
	然后进入 (下一个)【提议阶段】【H+1,0】

	 */
	// 处于等到CommitTime + timeoutCommit 的阶段
	RoundStepNewHeight     = RoundStepType(0x01) // Wait til CommitTime + timeoutCommit



	/**
	TODO 新一轮的开始阶段 【R+1】
	 */
	// 设置新轮并转到RoundStepPropose
	RoundStepNewRound      = RoundStepType(0x02) // Setup new round and go to RoundStepPropose






	/**
	TODO ###############################
	TODO 提议阶段  【H，R】
	步骤：
	指定提议者提议一个块

	结果：
	1、进入与投票阶段
		a、计数器1超时
		b、如果共识节点收到提议且达到POLC 阶段所需的预投票
	2、普通退出情况
	TODO -------------------------------
	 */
	/**
	发起提案，并广播提案
	 */
	RoundStepPropose       = RoundStepType(0x03) // Did propose, gossip proposal









	/**
	TODO ###############################
	TODO 预投票阶段   【H，R】
	步骤：
	每个验证人都要广播自己的预选投票。
	若在提议阶段提议的block是有效的，
	那么该验证节点统一该区块。
	如果block无效或者验证人在超时时间内未及时收到提议，
	则透出 <nil> 表示否决。

	结果：
	1、进入与预提交阶段
		a、收到超过 2/3 的(任意)预投票，但后来计数器2超时。
		b、对特定的块 同意/否决的预投票，超过 2/3
	2、普通退出情况
	TODO -------------------------------
	*/
	/**
	发起 prevote，并广播 prevote
	 */
	RoundStepPrevote       = RoundStepType(0x04) // Did prevote, gossip prevotes
	/**
	等待接收 x > 2/3 的 prevote (一个等待超时阶段)
	 */
	RoundStepPrevoteWait   = RoundStepType(0x05) // Did receive any +2/3 prevotes, start timeout









	/**
	TODO ###############################
	TODO 预提交阶段    【H，R】
	步骤：
	每个验证人都要广播自己的预提交 投票。
	如果验证人在【H，R】的POLC 回合同意该 block，
	那么该验证人将广播 (表示同意该区块的)预提交信息。
	否则，如果该验证人 否决 或者 为见证 POLC 回合，
	则将广播包含 <nil> 的预提交信息。

	结果：
	1、进入与 提议阶段 【H，R+1】阶段
		a、收到超过 2/3 的(任意)预 提交，但后来计数器3超时。
		b、对特定的块 <nil>的预提交，超过 2/3
	2、普通退出情况
	TODO -------------------------------
	*/
	/**
	发起 precommit，并广播 precommit
	 */
	RoundStepPrecommit     = RoundStepType(0x06) // Did precommit, gossip precommits
	/**
	等待接收 x > 2/3 的 precommit (一个等待超时阶段)
	 */
	RoundStepPrecommitWait = RoundStepType(0x07) // Did receive any +2/3 precommits, start timeout








	/**
	TODO ###############################
	TODO 提交阶段  (最终提交阶段)  【H】
	步骤：
	设置提交时间为当前时间。

	结果：
	一旦区块被接收，则进入新的高度阶段 【H+1】
	TODO -------------------------------
	/**
	最终的 commit 阶段
	 */
	RoundStepCommit        = RoundStepType(0x08) // Entered commit state machine
	// NOTE: RoundStepNewHeight acts as RoundStepCommitWait.

	// NOTE: Update IsValid method if you change this!
)

// IsValid returns true if the step is valid, false if unknown/undefined.
func (rs RoundStepType) IsValid() bool {
	return uint8(rs) >= 0x01 && uint8(rs) <= 0x08
}

// String returns a string
func (rs RoundStepType) String() string {
	switch rs {
	case RoundStepNewHeight:
		return "RoundStepNewHeight"
	case RoundStepNewRound:
		return "RoundStepNewRound"
	case RoundStepPropose:
		return "RoundStepPropose"
	case RoundStepPrevote:
		return "RoundStepPrevote"
	case RoundStepPrevoteWait:
		return "RoundStepPrevoteWait"
	case RoundStepPrecommit:
		return "RoundStepPrecommit"
	case RoundStepPrecommitWait:
		return "RoundStepPrecommitWait"
	case RoundStepCommit:
		return "RoundStepCommit"
	default:
		return "RoundStepUnknown" // Cannot panic.
	}
}

//-----------------------------------------------------------------------------

// RoundState defines the internal consensus state.
// NOTE: Not thread safe. Should only be manipulated by functions downstream
// of the cs.receiveRoutine
/**
TODO 重要
[轮次state]
RoundState定义了内部共识状态。
注意：不是线程安全的。 只应由下游功能操纵
cs.receiveRoutine
 */
type RoundState struct {
	// 需要打包的最新块高
	Height                    int64               `json:"height"` // Height we are working on
	// 共识的轮次
	Round                     int                 `json:"round"`
	// 现在处于共识的 第几步 （发起提议? prevote? precommit? commit?）
	Step                      RoundStepType       `json:"step"`
	// 共识开始时间？
	StartTime                 time.Time           `json:"start_time"`
	// 找到+2/3预先提交Block for Block的主观时间
	// 真正 commit的时间
	CommitTime                time.Time           `json:"commit_time"` // Subjective time when +2/3 precommits for Block at Round were found
	// 当前共识时的 验证人集合
	Validators                *types.ValidatorSet `json:"validators"`
	// 当前共识的 提案信息
	Proposal                  *types.Proposal     `json:"proposal"`
	// 被提案的 block
	ProposalBlock             *types.Block        `json:"proposal_block"`
	// TODO 暂时不知道干嘛的
	ProposalBlockParts        *types.PartSet      `json:"proposal_block_parts"`
	// 锁定的轮次
	LockedRound               int                 `json:"locked_round"`
	// 锁定的 block (是不是上一个块啊)
	LockedBlock               *types.Block        `json:"locked_block"`
	// 不知道干嘛的
	LockedBlockParts          *types.PartSet      `json:"locked_block_parts"`

	// 最后已知的POL轮次为非零有效块。
	ValidRound                int                 `json:"valid_round"`       // Last known round with POL for non-nil valid block.
	// 上面提到的最后一个POL块。
	ValidBlock                *types.Block        `json:"valid_block"`       // Last known block of POL mentioned above.
	ValidBlockParts           *types.PartSet      `json:"valid_block_parts"` // Last known block parts of POL metnioned above.
	// 当前共识的所有 prevote
	Votes                     *HeightVoteSet      `json:"votes"`
	// commit的轮次？
	CommitRound               int                 `json:"commit_round"` //
	// 上一个 precommit的 voteSet ？
	LastCommit                *types.VoteSet      `json:"last_commit"`  // Last precommits at Height-1
	// 当前共识的轮次中的所有验证人
	LastValidators            *types.ValidatorSet `json:"last_validators"`
	// 是否触发超时 precommit ？
	TriggeredTimeoutPrecommit bool                `json:"triggered_timeout_precommit"`
}

// Compressed version of the RoundState for use in RPC
type RoundStateSimple struct {
	HeightRoundStep   string          `json:"height/round/step"`
	StartTime         time.Time       `json:"start_time"`
	ProposalBlockHash cmn.HexBytes    `json:"proposal_block_hash"`
	LockedBlockHash   cmn.HexBytes    `json:"locked_block_hash"`
	ValidBlockHash    cmn.HexBytes    `json:"valid_block_hash"`
	Votes             json.RawMessage `json:"height_vote_set"`
}

// Compress the RoundState to RoundStateSimple
func (rs *RoundState) RoundStateSimple() RoundStateSimple {
	votesJSON, err := rs.Votes.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return RoundStateSimple{
		HeightRoundStep:   fmt.Sprintf("%d/%d/%d", rs.Height, rs.Round, rs.Step),
		StartTime:         rs.StartTime,
		ProposalBlockHash: rs.ProposalBlock.Hash(),
		LockedBlockHash:   rs.LockedBlock.Hash(),
		ValidBlockHash:    rs.ValidBlock.Hash(),
		Votes:             votesJSON,
	}
}

// NewRoundEvent returns the RoundState with proposer information as an event.
func (rs *RoundState) NewRoundEvent() types.EventDataNewRound {
	addr := rs.Validators.GetProposer().Address
	idx, _ := rs.Validators.GetByAddress(addr)

	return types.EventDataNewRound{
		Height: rs.Height,
		Round:  rs.Round,
		Step:   rs.Step.String(),
		Proposer: types.ValidatorInfo{
			Address: addr,
			Index:   idx,
		},
	}
}

// CompleteProposalEvent returns information about a proposed block as an event.
func (rs *RoundState) CompleteProposalEvent() types.EventDataCompleteProposal {
	// We must construct BlockID from ProposalBlock and ProposalBlockParts
	// cs.Proposal is not guaranteed to be set when this function is called
	blockId := types.BlockID{
		Hash:        rs.ProposalBlock.Hash(),
		PartsHeader: rs.ProposalBlockParts.Header(),
	}

	return types.EventDataCompleteProposal{
		Height:  rs.Height,
		Round:   rs.Round,
		Step:    rs.Step.String(),
		BlockID: blockId,
	}
}

// RoundStateEvent returns the H/R/S of the RoundState as an event.
func (rs *RoundState) RoundStateEvent() types.EventDataRoundState {
	return types.EventDataRoundState{
		Height: rs.Height,
		Round:  rs.Round,
		Step:   rs.Step.String(),
	}
}

// String returns a string
func (rs *RoundState) String() string {
	return rs.StringIndented("")
}

// StringIndented returns a string
func (rs *RoundState) StringIndented(indent string) string {
	return fmt.Sprintf(`RoundState{
%s  H:%v R:%v S:%v
%s  StartTime:     %v
%s  CommitTime:    %v
%s  Validators:    %v
%s  Proposal:      %v
%s  ProposalBlock: %v %v
%s  LockedRound:   %v
%s  LockedBlock:   %v %v
%s  ValidRound:   %v
%s  ValidBlock:   %v %v
%s  Votes:         %v
%s  LastCommit:    %v
%s  LastValidators:%v
%s}`,
		indent, rs.Height, rs.Round, rs.Step,
		indent, rs.StartTime,
		indent, rs.CommitTime,
		indent, rs.Validators.StringIndented(indent+"  "),
		indent, rs.Proposal,
		indent, rs.ProposalBlockParts.StringShort(), rs.ProposalBlock.StringShort(),
		indent, rs.LockedRound,
		indent, rs.LockedBlockParts.StringShort(), rs.LockedBlock.StringShort(),
		indent, rs.ValidRound,
		indent, rs.ValidBlockParts.StringShort(), rs.ValidBlock.StringShort(),
		indent, rs.Votes.StringIndented(indent+"  "),
		indent, rs.LastCommit.StringShort(),
		indent, rs.LastValidators.StringIndented(indent+"  "),
		indent)
}

// StringShort returns a string
func (rs *RoundState) StringShort() string {
	return fmt.Sprintf(`RoundState{H:%v R:%v S:%v ST:%v}`,
		rs.Height, rs.Round, rs.Step, rs.StartTime)
}

//-----------------------------------------------------------
// These methods are for Protobuf Compatibility

// Size returns the size of the amino encoding, in bytes.
func (rs *RoundStateSimple) Size() int {
	bs, _ := rs.Marshal()
	return len(bs)
}

// Marshal returns the amino encoding.
func (rs *RoundStateSimple) Marshal() ([]byte, error) {
	return cdc.MarshalBinaryBare(rs)
}

// MarshalTo calls Marshal and copies to the given buffer.
func (rs *RoundStateSimple) MarshalTo(data []byte) (int, error) {
	bs, err := rs.Marshal()
	if err != nil {
		return -1, err
	}
	return copy(data, bs), nil
}

// Unmarshal deserializes from amino encoded form.
func (rs *RoundStateSimple) Unmarshal(bs []byte) error {
	return cdc.UnmarshalBinaryBare(bs, rs)
}
