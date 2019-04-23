package merkle

import (
	amino "my-tendermint/go-amino"
)

var cdc *amino.Codec

func init() {
	cdc = amino.NewCodec()
	cdc.Seal()
}
