package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: sign <checksums.txt> <checksums.sig>")
		os.Exit(2)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("NODELUME_SIGNING_PRIVATE_KEY")))
	if err != nil {
		fatal(err)
	}
	var priv ed25519.PrivateKey
	if len(raw) == ed25519.SeedSize {
		priv = ed25519.NewKeyFromSeed(raw)
	} else if len(raw) == ed25519.PrivateKeySize {
		priv = ed25519.PrivateKey(raw)
	} else {
		fatal(fmt.Errorf("private key must decode to 32-byte seed or 64-byte private key"))
	}
	if want := strings.TrimSpace(os.Getenv("NODELUME_RELEASE_PUBLIC_KEY")); want != "" {
		got := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
		if got != want {
			fatal(fmt.Errorf("signing private key does not match release.pub"))
		}
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal(err)
	}
	sig := ed25519.Sign(priv, b)
	if err = os.WriteFile(os.Args[2], []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0644); err != nil {
		fatal(err)
	}
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
