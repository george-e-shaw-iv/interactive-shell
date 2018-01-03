package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/george-e-shaw-iv/interactive-shell/pkg/keys"
	"github.com/george-e-shaw-iv/interactive-shell/pkg/sshd"
)

func main() {
	if len(os.Args) > 1 {
		b, err := ioutil.ReadFile(os.Args[1])
		if err != nil {
			log.Fatalf("Fatal error trying to read new public key file: %s", err)
		}

		err = keys.AddAuthorizedKey(b)
		if err != nil {
			log.Fatalf("Fatal error trying to add new public key to authorized_keys file: %s", err)
		}
	}

	daemon := sshd.New(2222)
	log.Fatal(daemon.Listen())
}
