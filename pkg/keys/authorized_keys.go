package keys

import (
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"
)

func GetAuthorizedKeys() (map[string]bool, error) {
	b, err := ioutil.ReadFile("authorized_keys")
	if err != nil {
		return nil, err
	}

	auth := make(map[string]bool)
	for len(b) > 0 {
		pub, _, _, rest, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			return nil, err
		}

		auth[string(pub.Marshal())] = true
		b = rest
	}

	return auth, nil
}

func AddAuthorizedKey(b []byte) error {
	f, err := os.OpenFile("authorized_keys", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	if _, err = f.Write(b); err != nil {
		return err
	}

	if err = f.Close(); err != nil {
		return err
	}

	return nil
}
