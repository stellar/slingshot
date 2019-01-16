package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/chain/txvm/crypto/ed25519"
)

func main() {
	fmt.Println("Hello, playground")
	hexstr := "a3a47341325231bd9f05dc6399feb5036bafc42aeb815a7c1503854b2ac627e934b9027b3daa3c44339742bb7e2dc85d5b65962bd0ce1e11169964e6595467c0"
	bytes, _ := hex.DecodeString(hexstr)
	prv := ed25519.PrivateKey(bytes)
	pub := prv.Public()
	log.Printf("Public: %x", pub)
}
