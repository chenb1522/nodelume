package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

func main() {
	apply := flag.String("apply", "", "project root to update release.pub and installer trust anchors")
	flag.Parse()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}
	pub64 := base64.StdEncoding.EncodeToString(pub)
	priv64 := base64.StdEncoding.EncodeToString(priv)
	if *apply != "" {
		root, err := filepath.Abs(*apply)
		if err != nil {
			fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, "release.pub"), []byte(pub64+"\n"), 0644); err != nil {
			fatal(err)
		}
		re := regexp.MustCompile(`(?m)^RELEASE_PUB="[A-Za-z0-9+/=]+"$`)
		for _, name := range []string{"install-server.sh", "install-agent.sh"} {
			p := filepath.Join(root, "scripts", name)
			b, err := os.ReadFile(p)
			if err != nil {
				fatal(err)
			}
			n := re.ReplaceAll(b, []byte(`RELEASE_PUB="`+pub64+`"`))
			if string(n) == string(b) {
				fatal(fmt.Errorf("trust anchor not found in %s", p))
			}
			if err = os.WriteFile(p, n, 0755); err != nil {
				fatal(err)
			}
		}
		fmt.Println("Updated release.pub and installer trust anchors.")
	}
	fmt.Println("PUBLIC=" + pub64)
	fmt.Println("PRIVATE=" + priv64)
	fmt.Println("Store PRIVATE only as GitHub Actions secret NODELUME_SIGNING_PRIVATE_KEY; never commit it.")
}

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
