package sshd

import (
	"io/ioutil"
	"log"
	"strconv"

	"github.com/george-e-shaw-iv/interactive-shell/pkg/keys"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"strings"
	"fmt"
)

type sshd struct {
	Port   int
	server *ssh.Server
}

func interactiveHandler(session ssh.Session) {
	r := make([]byte, 1)

	for {
		_, err := io.WriteString(session, "Test Prompt: ")
		if err != nil {
			log.Printf("Writing error within session (fp:%s): %s", session.Context().Value("public-key-fp"), err)
			return
		}

		var msg []byte
		for {
			if _, err := session.Read(r); err != nil {
				log.Printf("Reading error within session (fp:%s): %s", session.Context().Value("public-key-fp"), err)
				return
			}

			//backspace
			if r[0] == 127 {
				msg = msg[:len(msg)-1]
				continue
			}

			//end of command
			if r[0] == 13 {
				break
			}
			msg = append(msg, r[0])
			io.WriteString(session, string(r[0]))
		}

		if strings.TrimSpace(string(msg)) == "exit" {
			log.Printf("Session (fp:%s) has closed", session.Context().Value("public-key-fp"))
			return
		}

		fmt.Println(msg)
		io.WriteString(session, "\n")
	}
}

func keyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	aKeys, err := keys.GetAuthorizedKeys()
	if err != nil {
		log.Fatalf("Error getting authorized_keys: %s", err)
		return false
	}

	if aKeys[string(key.Marshal())] {
		ctx.SetValue("public-key-fp", gossh.FingerprintSHA256(key))
		log.Printf("User \"%s\" has successfully logged in with key fingerprint: %s", ctx.User(), ctx.Value("public-key-fp"))
		return true
	}

	log.Printf("Unable to authenticate incoming connection: %s", gossh.FingerprintSHA256(key))
	return false
}

func New(port int) *sshd {
	s := &sshd{
		Port: port,
		server: &ssh.Server{
			Addr:             "localhost:" + strconv.Itoa(port),
			Handler:          interactiveHandler,
			PublicKeyHandler: keyHandler,
		},
	}

	b, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatalf("Fatal error reading host private key: %s", err)
	}

	k, err := gossh.ParsePrivateKey(b)
	if err != nil {
		log.Fatalf("Fatal error parsing host private key: %s", err)
	}

	s.server.AddHostKey(k)

	return s
}

func (s *sshd) Listen() error {
	return s.server.ListenAndServe()
}
