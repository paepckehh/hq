// package hq
package hq

// import
import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"
	"os"

	// waiting for upstream fix for hash.Hash interface
	// blake3f "github.com/zeebo/blake3"
	blake2bf "golang.org/x/crypto/blake2b"
	sha3f "golang.org/x/crypto/sha3"
	blake3f "paepcke.de/hq/blake3"
)

// const
const (
	_hashBlockSize = 1024 * 32
)

// message -> sphincs msg input hash
// this way we can sign extream large messages really fast, with minimal memory use, even on embedded systems
func getMSGHash(filename string) [HashSize]byte {
	file, err := os.Open(filename)
	if err != nil {
		errExit("unable to read file [" + filename + "]")
	}
	reader := io.Reader(file)
	h := blake3New512()
	var l int
	for {
		block := make([]byte, _hashBlockSize)
		l, _ = reader.Read(block)
		if l < _hashBlockSize {
			h.Write(block)
			break
		}
		h.Write(block)
	}
	file.Close()
	return setByte64(h.Sum(nil))
}

// blake2bWNew512 is a wrapper
func blake2bNew512() hash.Hash {
	t, _ := blake2bf.New512(nil)
	return t
}

// blake3New256 wrapper
func blake3New256() hash.Hash {
	return blake3f.New()
}

// blake3New512 wrapper
func blake3New512() hash.Hash {
	return blake3f.New512()
}

// blake3fix fixed [64]byte return
func blake3fix(in []byte) [HashSize]byte {
	return blake3f.Sum512(in)
}

// sha3fix fixed [64]byte return
func sha3fix(in []byte) [HashSize]byte {
	return sha3f.Sum512(in)
}

// generic simple sha512/sha3-512 sandwich wrap
func hashWrap512(in []byte) [HashSize]byte {
	h := sha512.Sum512(in)
	return sha3f.Sum512(h[:])
}

// generic simple sha512/sha3-256 sandwich wrap slice
func hashWrap256S(in []byte) []byte {
	h := sha512.Sum512(in)
	hsum := sha3f.Sum256(h[:])
	return hsum[:]
}

// preconfigured simplified api compatible/exchangeable[input/output] functions (alphabetical)
func sha2(message []byte) []byte     { return sha2E(message, nil, 512) }
func sha3(message []byte) []byte     { return sha3E(message, nil, 512) }
func shake128(message []byte) []byte { return shake128E(message, nil, 512) }
func shake256(message []byte) []byte { return shake256E(message, nil, 512) }
func blake2b(message []byte) []byte  { return blake2bE(message, nil, 512) }
func blake3(message []byte) []byte   { return blake3E(message, nil, 512) }

//
// [E]xtended interfaces
// including hmac/kmac and standard fixed size & interface definition
//

func sha2E(message, kmac []byte, size int) []byte {
	data := kmac
	data = append(data, message...)
	switch size {
	case 224:
		t := sha256.Sum224(data)
		return t[:]
	case 256:
		t := sha256.Sum256(data)
		return t[:]
	case 512:
		t := sha512.Sum512(data)
		return t[:]
	case 5224:
		t := sha512.Sum512_224(data)
		return t[:]
	case 5256:
		t := sha512.Sum512_256(data)
		return t[:]
	}
	panic("HASH SIZE ERROR [sha2]")
}

func sha3E(message, kmac []byte, size int) []byte {
	data := kmac
	data = append(data, message...)
	switch size {
	case 224:
		t := sha3f.Sum224(data)
		return t[:]
	case 256:
		t := sha3f.Sum256(data)
		return t[:]
	case 512:
		t := sha3f.Sum512(data)
		return t[:]
	}
	panic("HASH ERROR [Sha3]")
}

func blake3E(message, kmac []byte, size int) []byte {
	data := kmac
	data = append(data, message...)
	switch size {
	case 256:
		t := blake3f.Sum256(data)
		return t[:]
	case 512:
		t := blake3f.Sum512(data)
		return t[:]
	}
	panic("HASH ERROR [Blake3]")
}

func blake2bE(message, hmac []byte, size int) []byte {
	m := []byte(message)
	switch size {
	case 224:
		t := make([]byte, 28)
		h, _ := blake2bf.New(28, hmac)
		h.Write(m)
		t = h.Sum(t)
		return t[28:]
	case 256:
		t := make([]byte, 32)
		h, _ := blake2bf.New(32, hmac)
		h.Write(m)
		t = h.Sum(t)
		return t[32:]
	case 512:
		t := make([]byte, 64)
		h, _ := blake2bf.New(64, hmac)
		h.Write(m)
		t = h.Sum(t)
		return t[64:]
	}
	panic("HASH SIZE ERROR [Blake2b]")
}

func shake128E(message, kmac []byte, size int) []byte {
	data := kmac
	data = append(data, message...)
	switch size {
	case 224:
		t := make([]byte, 28)
		sha3f.ShakeSum128(t, data)
		return t
	case 256:
		t := make([]byte, 32)
		sha3f.ShakeSum128(t, data)
		return t
	case 512:
		t := make([]byte, 64)
		sha3f.ShakeSum128(t, data)
		return t
	case 65536:
		t := make([]byte, 8192)
		sha3f.ShakeSum128(t, data)
		return t
	}
	panic("HASH SIZE ERROR [Shake128]")
}

func shake256E(message, kmac []byte, size int) []byte {
	data := kmac
	data = append(data, message...)
	switch size {
	case 224:
		t := make([]byte, 28)
		sha3f.ShakeSum256(t, data)
		return t
	case 256:
		t := make([]byte, 32)
		sha3f.ShakeSum256(t, data)
		return t
	case 512:
		t := make([]byte, 64)
		sha3f.ShakeSum256(t, data)
		return t
	case 65536:
		t := make([]byte, 8192)
		sha3f.ShakeSum256(t, data)
		return t
	}
	panic("HASH SIZE ERROR [Shake256]")
}
