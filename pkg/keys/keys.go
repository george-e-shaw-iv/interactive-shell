package keys

import (
	"log"
	"os"
	"os/exec"
)

func init() {
	if _, err := os.Stat("authorized_keys"); os.IsNotExist(err) {
		log.Println("Warning: authorized_keys file does not exist. One will be created, however, in order for any user to authenticate keys must be added to said file. For more information on this file visit https://www.freebsd.org/cgi/man.cgi?sshd(8) and find the section on authorized_keys file format.")

		_, err := os.Create("authorized_keys")
		if err != nil {
			log.Fatalf("Fatal error creating authorized_keys file: %s", err)
		}
	}

	if _, err := os.Stat("id_rsa"); os.IsNotExist(err) {
		log.Println("Warning: The private host key used to prevent man-in-the-middle attacks has not yet been generated on this server, one will be created.")

		if err := exec.Command("ssh-keygen", "-t", "rsa", "-N", "", "-f", "id_rsa").Run(); err != nil {
			log.Fatalf("Fatal error generating host key-pair: %s", err)
		}
	}
}
