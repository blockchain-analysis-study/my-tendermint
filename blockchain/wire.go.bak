package blockchain

import (
	amino "my-tendermint/go-amino"
	"my-tendermint/tendermint/types"
)

var cdc = amino.NewCodec()

func init() {
	RegisterBlockchainMessages(cdc)
	types.RegisterBlockAmino(cdc)
}
