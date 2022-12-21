//go:build armbe || arm64be || mips || mips64 || mips64p32 || ppc || ppc64 || sparc || sparc64 || s390 || s390x

// package b64
package b64

// import
import (
	"math/bits"
	"unsafe"
)

// putTaill ...
func putTail(ptr uintptr, tail *[4]byte, n int) {
	switch n {
	case 3:
		*(*byte)(unsafe.Pointer(ptr)) = tail[3]
		*(*byte)(unsafe.Pointer(ptr + 1)) = tail[2]
		*(*byte)(unsafe.Pointer(ptr + 2)) = tail[1]
	case 2:
		*(*byte)(unsafe.Pointer(ptr)) = tail[3]
		*(*byte)(unsafe.Pointer(ptr + 1)) = tail[2]
	case 1:
		*(*byte)(unsafe.Pointer(ptr)) = tail[3]
	}
}

//go:nosplit
func bswap32(ptr uintptr) uint32 {
	return *(*uint32)(unsafe.Pointer(ptr))
}

//go:nosplit
func stou32(cp uintptr, x uint32) {
	*(*uint32)(unsafe.Pointer(cp)) = bits.ReverseBytes32(x)
}

//go:nosplit
func ctou32(cp uintptr) uint32 {
	return bits.ReverseBytes32(*(*uint32)(unsafe.Pointer(cp)))
}
