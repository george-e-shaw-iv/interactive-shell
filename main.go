package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/george-e-shaw-iv/interactive-shell/pkg/keys"
	"github.com/george-e-shaw-iv/interactive-shell/pkg/shell"
	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) > 1 {
		b, err := ioutil.ReadFile(os.Args[1])
		if err != nil {
			log.Fatalf("Fatal error trying to read new public key file: %s", err)
		}

		newAuthorizedKey, err := ssh.ParsePublicKey(b)
		if err != nil {
			log.Fatalf("Fatal error trying to parse new public key: %s", err)
		}

		err = keys.AddAuthorizedKey(newAuthorizedKey)
		if err != nil {
			log.Fatalf("Fatal error trying to add new public key to authorized_keys file: %s", err)
		}
	}

	s, err := shell.New(2222)
	if err != nil {
		log.Fatalf("Fatal error creating shell: %s", err)
	}

	log.Println("Interactive SSH server is listening for incoming connections.. To shutdown server press CTRL+C...")
	for {
		if err = s.Listen(); err != nil {
			log.Printf("Listener log: %s", err)
		}
	}
}
