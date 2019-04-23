package privval

import (
	cmn "my-tendermint/tendermint/libs/common"
)

// IsConnTimeout returns a boolean indicating whether the error is known to
// report that a connection timeout occurred. This detects both fundamental
// network timeouts, as well as ErrConnTimeout errors.
func IsConnTimeout(err error) bool {
	if cmnErr, ok := err.(cmn.Error); ok {
		if cmnErr.Data() == ErrConnTimeout {
			return true
		}
	}
	if _, ok := err.(timeoutError); ok {
		return true
	}
	return false
}
