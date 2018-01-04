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
	"bytes"
	"os/exec"
)

var allowedCommands = []string{
	"ls", "cd", "rm", "mkdir", "touch",
}

type sshd struct {
	Port   int
	server *ssh.Server
}

func interactiveHandler(session ssh.Session) {
	r := make([]byte, 1)

	for {
		pwd, err := exec.Command("pwd").Output()

		_, err = io.WriteString(session, session.User()+"@"+session.RemoteAddr().String()+":"+strings.TrimSpace(string(pwd))+"$ ")
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
				if len(msg) > 0 {
					msg = msg[:len(msg)-1]
					io.WriteString(session, "\b")
				}
				continue
			}

			//end of command
			if r[0] == 13 {
				break
			}
			msg = append(msg, r[0])
			io.WriteString(session, string(r[0]))
		}

		io.WriteString(session, "\n")

		if strings.TrimSpace(string(msg)) == "exit" {
			err = session.Exit(0)
			if err != nil {
				log.Printf("Exiting error within session (fp:%s): %s", session.Context().Value("public-key-fp"), err)
			}

			log.Printf("Session (fp:%s) has closed", session.Context().Value("public-key-fp"))
			return
		}

		splitCommand := strings.Split(string(msg), " ")
		args := splitCommand[1:]

		cmdOk := false
		for _, command := range allowedCommands {
			if splitCommand[0] == command {
				cmdOk = true
				break
			}
		}

		if !cmdOk {
			io.WriteString(session, "Command \""+splitCommand[0]+"\" is not allowed by the server.\n")
			continue
		}

		var cmdout bytes.Buffer
		var cmderr bytes.Buffer

		cmd := exec.Command(splitCommand[0], args...)
		cmd.Stdout = &cmdout
		cmd.Stderr = &cmderr

		err = cmd.Run()
		if err != nil {
			io.WriteString(session, fmt.Sprint(err) + ": " + cmderr.String() + "\n")
			continue
		}
		io.WriteString(session, cmdout.String())

		fmt.Println(splitCommand[0])
		fmt.Println(args)
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
