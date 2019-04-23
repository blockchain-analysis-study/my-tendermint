package types

import (
	amino "my-tendermint/go-amino"
	"my-tendermint/tendermint/types"
)

var cdc = amino.NewCodec()

func init() {
	types.RegisterBlockAmino(cdc)
}
