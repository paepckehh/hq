// package b64 ...
// [2022/02/03] [paepcke.de/internal/b64] fork [github.com/cristalhq/base64]
// [speedup|slim-down] version - please dont use outside this fork outside this
// special use case, please use always the original
//
// [github.com/cristalhq/base64] based on [https://github.com/powturbo/Turbo-Base64]
// Copyright (c) 2021 cristaltech - MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package b64

import (
	"errors"
	"math"
	"unsafe"
)

//
// EXTERNAL INTERFACE
//

// Encoding ..
type Encoding struct {
	lutSe  [64]byte
	lutXe  [4096]uint32
	lutXd0 [256]uint32
	lutXd1 [256]uint32
	lutXd2 [256]uint32
	lutXd3 [256]uint32
}

// NewEncoding ...
func NewEncoding(lutSe [64]byte) *Encoding {
	lutXe, lutXd0, lutXd1, lutXd2, lutXd3 := makeLuts(stdLutSe)
	return &Encoding{
		lutSe:  stdLutSe,
		lutXe:  lutXe,
		lutXd0: lutXd0,
		lutXd1: lutXd1,
		lutXd2: lutXd2,
		lutXd3: lutXd3,
	}
}

// EncodeToBytes ...
func (e *Encoding) EncodeToBytes(src []byte) []byte {
	if len(src) == 0 {
		return []byte{}
	}
	length := (len(src)*8 + 5) / 6
	result := make([]byte, length)
	e.encode(result, src, uintptr(length))
	return result
}

// DecodeToBytes ...
func (e *Encoding) DecodeToBytes(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return []byte{}, nil
	}
	x := len(src)
	sf := 0
	if x > 4 {
		sf++
	}
	length := x*6/8 + sf
	if length == 0 {
		return nil, ErrWrongData
	}
	result := make([]byte, length)
	n := e.decode(result, src)
	if n == 0 {
		return nil, ErrWrongData
	}
	(*sliceHeader)(unsafe.Pointer(&result)).len = n
	return result, nil
}

//
// INTERNAL BACKEND
//

var (
	stdLutSe = [64]byte{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
	}
	StdEncoding  = NewEncoding(stdLutSe)
	ErrWrongData = errors.New("wrong base64 data")
)

type sliceHeader struct {
	data uintptr
	len  int
	cap  int
}

func makeLuts(lutSe [64]byte) ([4096]uint32, [256]uint32, [256]uint32, [256]uint32, [256]uint32) {
	lutXe := [4096]uint32{}
	lutXd0 := [256]uint32{}
	lutXd1 := [256]uint32{}
	lutXd2 := [256]uint32{}
	lutXd3 := [256]uint32{}
	for i := 0; i < 256; i++ {
		lutXd0[i] = math.MaxUint32
		lutXd1[i] = math.MaxUint32
		lutXd2[i] = math.MaxUint32
		lutXd3[i] = math.MaxUint32
	}
	for i, ichar := range lutSe {
		for j, jchar := range lutSe {
			lutXe[j+i*64] = uint32(ichar) | uint32(jchar)<<8
		}
		lutXd0[ichar] = uint32(i * 4)
		d1 := uint32(i * 16)
		lutXd1[ichar] = (d1<<8)&0x0000FF00 | (d1>>8)&0x00000000FF
		d2 := uint32(i * 64)
		lutXd2[ichar] = (d2<<16)&0x00FF0000 | d2&0x0000FF00
		lutXd3[ichar] = uint32(i) << 16
	}
	return lutXe, lutXd0, lutXd1, lutXd2, lutXd3
}

//go:nosplit
func (e *Encoding) decode(dst, src []byte) int {
	dstlen := uintptr(len(dst))
	srclen := uintptr(len(src))
	if srclen == 0 {
		return 0
	}
	ip := (*sliceHeader)(unsafe.Pointer(&src)).data
	ipstart := ip
	op := (*sliceHeader)(unsafe.Pointer(&dst)).data
	opstart := op
	var cu uint32
	if srclen >= 8+4 {
		ux := ctou32(ip)
		vx := ctou32(ip + 4)
		for ip < (ipstart+srclen)-(128+4) {
			{
				_u := ux
				ux = ctou32(ip + 8 + 0*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+0*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 0*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+0*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 1*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+1*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 1*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+1*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 2*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+2*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 2*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+2*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 3*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+3*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 3*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+3*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 4*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+4*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 4*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+4*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 5*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+5*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 5*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+5*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 6*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+6*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 6*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+6*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 7*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+7*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 7*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+7*6+3, _v)
			}

			{
				_u := ux
				ux = ctou32(ip + 8 + 8*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+8*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 8*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+8*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 9*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+9*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 9*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+9*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 10*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+10*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 10*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+10*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 11*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+11*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 11*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+11*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 12*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+12*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 12*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+12*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 13*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+13*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 13*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+13*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 14*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+14*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 14*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+14*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 15*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+15*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 15*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+15*6+3, _v)
			}
			ip += 128
			op += (128 / 4) * 3
		}
		for ip < (ipstart+srclen)-(16+4) {
			{
				_u := ux
				ux = ctou32(ip + 8 + 0*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+0*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 0*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+0*6+3, _v)
			}
			{
				_u := ux
				ux = ctou32(ip + 8 + 1*8)
				_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
				cu |= _u
				stou32(op+1*6, _u)
				_v := vx
				vx = ctou32(ip + 8 + 1*8 + 4)
				_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
				cu |= _v
				stou32(op+1*6+3, _v)
			}
			ip += 16
			op += (16 / 4) * 3
		}
		if ip < (ipstart+srclen)-(8+4) {
			_u := ux
			_u = (e.lutXd0[byte(_u)] | e.lutXd1[byte(_u>>8)] | e.lutXd2[byte(_u>>16)] | e.lutXd3[_u>>24])
			cu |= _u
			stou32(op+0*6, _u)
			_v := vx
			_v = (e.lutXd0[byte(_v)] | e.lutXd1[byte(_v>>8)] | e.lutXd2[byte(_v>>16)] | e.lutXd3[_v>>24])
			cu |= _v
			stou32(op+0*6+3, _v)
			ip += 8
			op += (8 / 4) * 3
		}
	}
	for ip < (ipstart+srclen)-4 {
		u := ctou32(ip)
		u = (e.lutXd0[byte(u)] | e.lutXd1[byte(u>>8)] | e.lutXd2[byte(u>>16)] | e.lutXd3[u>>24])
		stou32(op, u)
		cu |= u
		ip += 4
		op += 3
	}
	var u uint32
	l := (ipstart + srclen) - ip
	up := (*[4]byte)(unsafe.Pointer(&u))
	switch l {
	case 4:
		if op-opstart+3 > dstlen {
			return 0
		}
		u = ctou32(ip)
		u = (e.lutXd0[byte(u)] | e.lutXd1[byte(u>>8)] | e.lutXd2[byte(u>>16)] | e.lutXd3[u>>24])
		putTail(op, up, 3)
		op += 3
		cu |= u
	case 3:
		if op-opstart+2 > dstlen {
			return 0
		}
		u = e.lutXd0[*(*byte)(unsafe.Pointer(ip + 0))] | e.lutXd1[*(*byte)(unsafe.Pointer(ip + 1))] | e.lutXd2[*(*byte)(unsafe.Pointer(ip + 2))]
		putTail(op, up, 2)
		op += 2
		cu |= u
	case 2:
		if op-opstart >= dstlen {
			return 0
		}
		u = e.lutXd0[*(*byte)(unsafe.Pointer(ip + 0))] | e.lutXd1[*(*byte)(unsafe.Pointer(ip + 1))]
		putTail(op, up, 1)
		op++
		cu |= u
	case 1:
		return 0
	}
	if cu == 0xffffffff {
		return 0
	}
	return int(op - opstart)
}

//go:nosplit
func (e *Encoding) encode(dst, src []byte, outlen uintptr) {
	inlen := len(src)
	ip := (*sliceHeader)(unsafe.Pointer(&src)).data
	ipstart := ip
	op := (*sliceHeader)(unsafe.Pointer(&dst)).data
	opstart := op
	if outlen >= 8+12 {
		u0x := bswap32(ip)
		u1x := bswap32(ip + 3)
		for op <= (opstart+outlen)-(128+12) {
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 0*6)
				u1x = bswap32(ip + 6 + 0*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+0*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+0*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 1*6)
				u1x = bswap32(ip + 6 + 1*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+1*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+1*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 2*6)
				u1x = bswap32(ip + 6 + 2*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+2*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+2*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 3*6)
				u1x = bswap32(ip + 6 + 3*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+3*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+3*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 4*6)
				u1x = bswap32(ip + 6 + 4*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+4*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+4*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 5*6)
				u1x = bswap32(ip + 6 + 5*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+5*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+5*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 6*6)
				u1x = bswap32(ip + 6 + 6*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+6*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+6*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 7*6)
				u1x = bswap32(ip + 6 + 7*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+7*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+7*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 8*6)
				u1x = bswap32(ip + 6 + 8*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+8*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+8*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 9*6)
				u1x = bswap32(ip + 6 + 9*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+9*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+9*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 10*6)
				u1x = bswap32(ip + 6 + 10*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+10*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+10*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 11*6)
				u1x = bswap32(ip + 6 + 11*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+11*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+11*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 12*6)
				u1x = bswap32(ip + 6 + 12*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+12*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+12*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 13*6)
				u1x = bswap32(ip + 6 + 13*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+13*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+13*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 14*6)
				u1x = bswap32(ip + 6 + 14*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+14*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+14*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 15*6)
				u1x = bswap32(ip + 6 + 15*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+15*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+15*8+4, _u1)
			}
			op += 128
			ip += (128 / 4) * 3
		}
		for op <= (opstart+outlen)-(16+12) {
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 0*6)
				u1x = bswap32(ip + 6 + 0*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+0*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+0*8+4, _u1)
			}
			{
				_u0, _u1 := u0x, u1x
				u0x = bswap32(ip + 6 + 1*6)
				u1x = bswap32(ip + 6 + 1*6 + 3)
				_u0 = e.lutXe[(_u0>>8)&0xfff]<<16 | e.lutXe[_u0>>20]
				stou32(op+1*8, _u0)
				_u1 = e.lutXe[(_u1>>8)&0xfff]<<16 | e.lutXe[_u1>>20]
				stou32(op+1*8+4, _u1)
			}
			op += 16
			ip += (16 / 4) * 3
		}
		if op <= (opstart+outlen)-(8+12) {
			_u0 := e.lutXe[(u0x>>8)&0xfff]<<16 | e.lutXe[u0x>>20]
			stou32(op+0*8, _u0)
			_u1 := e.lutXe[(u1x>>8)&0xfff]<<16 | e.lutXe[u1x>>20]
			stou32(op+0*8+4, _u1)
			op += 8
			ip += (8 / 4) * 3
		}
	}
	for op < (opstart+outlen)-4 {
		_u := bswap32(ip)
		stou32(op, e.lutXe[(_u>>8)&0xfff]<<16|e.lutXe[_u>>20])
		op += 4
		ip += 3
	}
	_l := uint32((ipstart + uintptr(inlen)) - ip)
	if _l == 3 {
		_u := uint32(*(*byte)(unsafe.Pointer(ip + 0)))<<24 | uint32(*(*byte)(unsafe.Pointer(ip + 1)))<<16 | uint32(*(*byte)(unsafe.Pointer(ip + 2)))<<8
		stou32(op, uint32(e.lutSe[(_u>>8)&0x3f])<<24|uint32(e.lutSe[(_u>>14)&0x3f])<<16|uint32(e.lutSe[(_u>>20)&0x3f])<<8|uint32(e.lutSe[(_u>>26)&0x3f]))
	} else if _l != 0 {
		*(*byte)(unsafe.Pointer(op)) = e.lutSe[(*(*byte)(unsafe.Pointer(ip + 0))>>2)&0x3f]
		op++
		if _l == 2 {
			*(*byte)(unsafe.Pointer(op)) = e.lutSe[(*(*byte)(unsafe.Pointer(ip + 0))&0x3)<<4|(*(*byte)(unsafe.Pointer(ip + 1))&0xf0)>>4]
			op++
			*(*byte)(unsafe.Pointer(op)) = e.lutSe[(*(*byte)(unsafe.Pointer(ip + 1))&0xf)<<2]
			op++
		} else {
			*(*byte)(unsafe.Pointer(op)) = e.lutSe[(*(*byte)(unsafe.Pointer(ip + 0))&0x3)<<4]
			op++
		}
	}
}
