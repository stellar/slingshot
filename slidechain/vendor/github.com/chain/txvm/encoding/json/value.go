package json

import "errors"

type Value int

const (
	Unknown Value = iota
	String
	Number
	Object
	Array
	True
	False
	Null
)

func ValueType(data []byte) (Value, error) {
	var first byte
	for _, c := range data {
		if !isSpace(c) {
			first = c
			break
		}
	}
	switch first {
	case 'n':
		return Null, nil
	case 't':
		return True, nil
	case 'f':
		return False, nil
	case '[':
		return Array, nil
	case '{':
		return Object, nil
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return Number, nil
	case '"':
		return String, nil
	}
	return Unknown, errors.New("unknown json value type")
}

// taken from std encoding/json
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
