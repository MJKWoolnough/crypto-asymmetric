# asymmetric
--
    import "github.com/MJKWoolnough/crypto-asymmetric"

Package asymmetric handles the loading of rsa public and private keys and the
signing of arbitrary objects.

## Usage

#### func  PrivateKey

```go
func PrivateKey(f io.Reader) (*rsa.PrivateKey, error)
```
PublicKey tries to read a rsa private key from the given reader.

#### func  PublicKey

```go
func PublicKey(f io.Reader) (*rsa.PublicKey, error)
```
PublicKey tries to read a rsa public key from the given reader.

#### func  Sign

```go
func Sign(value interface{}, key *rsa.PrivateKey) ([]byte, error)
```
Sign takes a value and signs it with the given key.

#### func  SignCheck

```go
func SignCheck(value interface{}, signature []byte, key *rsa.PublicKey) error
```
SignCheck verifies that the values signature is valid for the given key.
