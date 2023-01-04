package hq

import (
	"crypto/sha512"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	sha3f "golang.org/x/crypto/sha3"
)

// simplified api compatible/exchangeable[input/output] functions
func pbkdf2Sha2(p, s []byte, r int) []byte   { return pbkdf2.Key(p, s, r, 512, sha512.New) }
func pbkdf2Sha3(p, s []byte, r int) []byte   { return pbkdf2.Key(p, s, r, 512, sha3f.New512) }
func pbkdf2Blake3(p, s []byte, r int) []byte { return pbkdf2.Key(p, s, r, 512, blake3New512) }
func argon2d(p, s []byte) []byte {
	return argon2.Key(p, s, 5, uint32(_memlimit), uint8(_parallel), 512)
}
