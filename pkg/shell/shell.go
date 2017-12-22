package shell

import "golang.org/x/crypto/ssh"

type shell struct {
	accessPort int
	config     *ssh.ServerConfig
}

func New(port int) *shell {
	return &shell{
		accessPort: port,
		config: &ssh.ServerConfig{
			MaxAuthTries: 3,
			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				return nil, nil
			},
		},
	}
}
