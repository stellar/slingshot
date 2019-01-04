package txvm

import (
	"fmt"

	"github.com/chain/txvm/errors"
)

type vmError error

func errorf(msg string, arg ...interface{}) error {
	return vmError(fmt.Errorf(msg, arg...))
}

func (vm *VM) wraperr(e error) error {
	return errors.WithData(e, "vm", vm)
}
