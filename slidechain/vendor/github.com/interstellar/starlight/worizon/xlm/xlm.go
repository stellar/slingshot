package xlm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var errInvalidHorizonStr = errors.New("invalid horizon balance string")

// Amount represents a quantity of XLM as an int64 count of stroops.
type Amount int64

// Common amounts.
//
// To count the number of units in an Amount, divide:
//   lumen := xlm.Lumen
//   fmt.Print(int64(lumen/xlm.Stroop)) // prints 10000000
//
// To convert an integer number of units to an Amount, multiply:
//   lumens := 10
//   fmt.Print(xlm.Amount(lumens)*xlm.Lumen) // prints 10XLM
const (
	Stroop     Amount = 1
	Microlumen        = 10 * Stroop
	Millilumen        = 1000 * Microlumen
	Lumen             = 1000 * Millilumen
)

func (n Amount) String() string {
	sign, u := "", uint64(n)
	neg := n < 0
	if neg {
		sign, u = "-", -u
	}

	var (
		denom uint64
		prec  int
		unit  string
	)

	switch {
	case u == 0:
		return "0 XLM"
	case u == 1:
		return sign + "1 stroop"
	case u < uint64(Microlumen): // print stroops
		return fmt.Sprintf("%d stroops", n)
	case u < uint64(Millilumen): // print microlumens
		denom, prec, unit = 10, 1, "µXLM"
	case u < uint64(Lumen): // print millilumens
		denom, prec, unit = 10000, 4, "mXLM"
	default:
		denom, prec, unit = 10000000, 7, "XLM"
	}

	whole, frac := u/denom, u%denom
	return fmt.Sprintf("%s%d%s %s", sign, whole, fmtFrac(frac, prec), unit)
}

// HorizonString returns the Amount in decimal form in terms of Lumens,
// required for building transactions to be submitted to Horizon.
func (n Amount) HorizonString() string {
	sign, coeff := "", 1
	if n < 0 {
		sign, coeff = "-", -1
	}
	u := uint64(Amount(coeff) * n)
	denom := uint64(10000000)
	whole, frac := u/denom, u%denom
	return fmt.Sprintf("%s%d%s", sign, whole, fmtFrac(frac, 7))
}

// Parse converts a Horizon balance string to an Amount.
func Parse(horizonString string) (Amount, error) {
	splits := strings.Split(horizonString, ".")
	if len(splits) > 2 || len(splits) == 0 {
		return 0, errInvalidHorizonStr
	}
	intPart, err := strconv.ParseInt(splits[0], 10, 64)
	if err != nil {
		return 0, errInvalidHorizonStr
	}
	if len(splits) == 1 {
		return Lumen * Amount(intPart), nil
	}

	if len(splits[1]) > 7 {
		return 0, errInvalidHorizonStr
	}
	// Right-pad the fractional part of Horizon balance to be the
	// correct number of Stroops.
	fracPartStr := splits[1] + strings.Repeat("0", 7-len(splits[1]))
	amountStr := splits[0] + fracPartStr
	amount, err := strconv.ParseInt(amountStr, 10, 64)
	if err != nil {
		return 0, errInvalidHorizonStr
	}
	return Amount(amount), nil
}

func fmtFrac(u uint64, prec int) string {
	if u == 0 {
		return ""
	}
	s := fmt.Sprintf(".%0*d", prec, u)
	return strings.TrimRight(s, "0")
}
