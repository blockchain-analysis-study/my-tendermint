package consensus

import (
	amino "my-tendermint/go-amino"
	"my-tendermint/tendermint/types"
)

var cdc = amino.NewCodec()

func init() {
	RegisterConsensusMessages(cdc)
	RegisterWALMessages(cdc)
	types.RegisterBlockAmino(cdc)
}
