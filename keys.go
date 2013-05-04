// Copyright (c) 2013 - Michael Woolnough <michael.woolnough@gmail.com>
// 
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met: 
// 
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer. 
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution. 
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package asymmetric handles the loading of rsa public and private keys and the
// signing of arbitrary objects.

package asymmetric

import (
	"encoding/binary"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
)

type keyError struct {
	err string
}

func (e keyError) Error() string {
	return e.err
}

const (
	err_invalid = keyError { "Invalid Public Key Format" }
	err_noKey   = keyError { "No key found!" }
)

// PublicKey tries to read a rsa public key from the given reader.
func PublicKey(f io.Reader) (*rsa.PublicKey, error) {
        data := make([]byte, 8)
	if err := binary.Read(f, binary.BigEndian, &data); err != nil {
		return nil, err
	}
	if string(data) != "ssh-rsa " {
		return nil, err_invalid
	}
	d := base64.NewDecoder(base64.StdEncoding, f)
	var size int32
	if err := binary.Read(d, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	data = make([]byte, size)
	if err := binary.Read(d, binary.BigEndian, &data); err != nil {
		return nil, err
	}
	if string(data) != "ssh-rsa" {
		return nil, err_invalid
	}
	if err := binary.Read(d, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	data = make([]byte, size)
	if err := binary.Read(d, binary.BigEndian, &data); err != nil {
		return nil, err
	}
	e := int(0)
	pos := uint(0)
	for i := size - 1; i >=0; i-- {
		e |= int(uint32(data[i]) << pos)
		pos += 8
	}
	if err := binary.Read(d, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	data = make([]byte, size)
	if err := binary.Read(d, binary.BigEndian, &data); err != nil {
		return nil, err
	}
	return &rsa.PublicKey{new(big.Int).SetBytes(data), e}, nil
}

// PublicKey tries to read a rsa private key from the given reader.
func PrivateKey(f io.Reader) (*rsa.PrivateKey, error) {
	key := new(bytes.Buffer)
	if _, err := key.ReadFrom(f); err != nil {
		return nil, err
	}
	b, _ := pem.Decode(key.Bytes())
	if b == nil {
		return nil, err_noKey
	}
	rsa, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa, nil
}