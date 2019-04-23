package monitor

import (
	amino "my-tendermint/go-amino"
	ctypes "my-tendermint/tendermint/rpc/core/types"
)

var cdc = amino.NewCodec()

func init() {
	ctypes.RegisterAmino(cdc)
}
