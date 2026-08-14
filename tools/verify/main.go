package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: nodelume-verify PUBLIC_KEY CHECKSUMS SIGNATURE")
		os.Exit(2)
	}
	pkb, e := os.ReadFile(os.Args[1])
	if e != nil {
		fail(e)
	}
	pk, e := base64.StdEncoding.DecodeString(string(trim(pkb)))
	if e != nil || len(pk) != ed25519.PublicKeySize {
		fail(fmt.Errorf("invalid public key"))
	}
	msg, e := os.ReadFile(os.Args[2])
	if e != nil {
		fail(e)
	}
	sb, e := os.ReadFile(os.Args[3])
	if e != nil {
		fail(e)
	}
	sig, e := base64.StdEncoding.DecodeString(string(trim(sb)))
	if e != nil || !ed25519.Verify(ed25519.PublicKey(pk), msg, sig) {
		fail(fmt.Errorf("signature verification failed"))
	}
	fmt.Println("OK")
}
func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
