package cubetoken

import (
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	sha3f "golang.org/x/crypto/sha3"
	"paepcke.de/hq/scrypt" // x/crypto/scrypt needs upstream patch [kdf typical hash.Hash is is not exposed]
)

// simplified api compatible/exchangeable[input/output] functions
func argon2d(p, s []byte, memlimit, parallel int) []byte {
	return argon2.Key(p, s, 5, uint32(memlimit), uint8(parallel), 512)
}
func pbkdf2Sha2(p, s []byte, r int) []byte    { return pbkdf2.Key(p, s, r, 512, sha512.New) }
func pbkdf2Sha3(p, s []byte, r int) []byte    { return pbkdf2.Key(p, s, r, 512, sha3f.New512) }
func pbkdf2Blake2b(p, s []byte, r int) []byte { return pbkdf2.Key(p, s, r, 512, blake2bNew512) }
func pbkdf2Blake3(p, s []byte, r int) []byte  { return pbkdf2.Key(p, s, r, 512, blake3New512) }
func scryptSha2(p, s []byte, r int) []byte    { return scryptE(p, s, 16384, r, 1, 512, sha512.New) }
func scryptSha3(p, s []byte, r int) []byte    { return scryptE(p, s, 16384, r, 1, 512, sha3f.New512) }
func scryptBlake2b(p, s []byte, r int) []byte { return scryptE(p, s, 16384, r, 1, 512, blake2bNew512) }
func scryptBlake3(p, s []byte, r int) []byte  { return scryptE(p, s, 16384, r, 1, 512, blake3New512) }

func scryptE(p, s []byte, n, r, a, k int, h func() hash.Hash) []byte {
	result, _ := scrypt.NewKey(p, s, n, r, a, k, h)
	return result
}
