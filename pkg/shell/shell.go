package shell

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"

	"github.com/george-e-shaw-iv/interactive-shell/pkg/keys"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type shell struct {
	accessPort int
	listener   net.Listener
	config     *ssh.ServerConfig
}

func New(port int) (*shell, error) {
	s := &shell{
		accessPort: port,
		config: &ssh.ServerConfig{
			MaxAuthTries: 3,
			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				aKeys, err := keys.GetAuthorizedKeys()
				if err != nil {
					fmt.Errorf("Error authorizing key: %s", err)
					return nil, err
				}

				if aKeys[string(key.Marshal())] {
					return &ssh.Permissions{
						Extensions: map[string]string{
							"pubkey-fp": ssh.FingerprintSHA256(key),
						},
					}, nil
				}

				fmt.Errorf("could not authorize public key")
				return nil, errors.New("could not authorize public key")
			},
		},
	}

	b, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		return nil, err
	}

	p, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, err
	}

	s.config.AddHostKey(p)

	s.listener, err = net.Listen("tcp", "localhost:"+strconv.Itoa(s.accessPort))
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *shell) Listen() error {
	inConn, err := s.listener.Accept()
	if err != nil {
		return err
	}

	conn, chans, reqs, err := ssh.NewServerConn(inConn, s.config)
	if err != nil {
		return err
	}
	log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return err
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				req.Reply(req.Type == "shell", nil)
			}
		}(requests)

		term := terminal.NewTerminal(channel, "> ")

		go func() {
			defer channel.Close()
			for {
				line, err := term.ReadLine()
				if err != nil {
					break
				}
				fmt.Println(line)
			}
		}()
	}

	return nil
}
