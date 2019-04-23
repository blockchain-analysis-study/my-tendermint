package types

// SignedMsgType is a type of signed message in the consensus.
type SignedMsgType byte

const (
	// Votes
	// 发起投票
	PrevoteType   SignedMsgType = 0x01
	// 发起 precommit
	PrecommitType SignedMsgType = 0x02

	// Proposals
	// 发起提案
	ProposalType SignedMsgType = 0x20
)

// IsVoteTypeValid returns true if t is a valid vote type.
func IsVoteTypeValid(t SignedMsgType) bool {
	switch t {
	case PrevoteType, PrecommitType:
		return true
	default:
		return false
	}
}
