//go:build 386 || amd64 || amd64p32 || arm || arm64 || mipsle || mips64le || mips64p32le || ppc64le || riscv || riscv64 || wasm

// package b64
package b64

// import
import (
	"math/bits"
	"unsafe"
)

// putTail ...
func putTail(ptr uintptr, tail *[4]byte, n int) {
	switch n {
	case 3:
		*(*byte)(unsafe.Pointer(ptr)) = tail[0]
		*(*byte)(unsafe.Pointer(ptr + 1)) = tail[1]
		*(*byte)(unsafe.Pointer(ptr + 2)) = tail[2]
	case 2:
		*(*byte)(unsafe.Pointer(ptr)) = tail[0]
		*(*byte)(unsafe.Pointer(ptr + 1)) = tail[1]
	case 1:
		*(*byte)(unsafe.Pointer(ptr)) = tail[0]
	}
}

//go:nosplit
func bswap32(ptr uintptr) uint32 {
	return bits.ReverseBytes32(*(*uint32)(unsafe.Pointer(ptr)))
}

//go:nosplit
func stou32(cp uintptr, x uint32) {
	*(*uint32)(unsafe.Pointer(cp)) = x
}

//go:nosplit
func ctou32(cp uintptr) uint32 {
	return *(*uint32)(unsafe.Pointer(cp))
}
