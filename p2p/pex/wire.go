package pex

import (
	amino "my-tendermint/go-amino"
)

var cdc *amino.Codec = amino.NewCodec()

func init() {
	RegisterPexMessage(cdc)
}
