package core_types

import (
	amino "my-tendermint/go-amino"
	"my-tendermint/tendermint/types"
)

func RegisterAmino(cdc *amino.Codec) {
	types.RegisterEventDatas(cdc)
	types.RegisterBlockAmino(cdc)
}
