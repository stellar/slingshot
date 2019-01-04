package ed25519

import (
	"bytes"
	"encoding/json"

	i10rjson "github.com/chain/txvm/encoding/json"
)

// UnmarshalJSON satisfies the json.Unmarshaler interface.
func (pub *PublicKey) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		return nil
	}
	return json.Unmarshal(b, (*i10rjson.HexBytes)(pub))
}

// MarshalJSON satisfies the json.Marshaler interface.
func (pub PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(i10rjson.HexBytes(pub))
}
