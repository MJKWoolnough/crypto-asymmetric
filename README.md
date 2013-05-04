PACKAGE

package asymmetric
    import "/home/michael/Programming/Go/src/github.com/MJKWoolnough/crypto-asymmetric"


FUNCTIONS

func PrivateKey(f io.Reader) (*rsa.PrivateKey, error)
    PublicKey tries to read a rsa private key from the given reader.

func PublicKey(f io.Reader) (*rsa.PublicKey, error)
    PublicKey tries to read a rsa public key from the given reader.

func Sign(value interface{}, key *rsa.PrivateKey) ([]byte, error)
    Sign takes a value and signs it with the given key.

func SignCheck(value interface{}, signature []byte, key *rsa.PublicKey) error
    SignCheck verifies that the values signature is valid for the given key.


