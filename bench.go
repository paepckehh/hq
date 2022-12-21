package hq

import (
	"strconv"
	"time"

	"paepcke.de/hq/cubetoken"
	"paepcke.de/sphincs"
)

const (
	_benchSlow = 6
	_benchFast = 60
	_OP        = "/op"
)

// Bench ...
func (c *Config) bench() bool {
	t0 := time.Now()
	id := NewHQ(c)
	id.ID.OWNER = pad(_testVectorOwner)
	id.IO.HashPassONE = hashWrap512([]byte(_testVectorPassOne))
	id.IO.HashPassTWO = hashWrap512([]byte(_testVectorPassTwo))
	id.IO.TSS = strconv.FormatInt(id.IO.Start.Unix(), 10)
	out("\nPrepare: [g]enerate & [u]nlock identity!")
	id.IO.Start = time.Now()
	id.genSphincs()
	id.report()
	id.IO.TSS = strconv.FormatInt(id.IO.Start.Unix(), 10)
	id.IO.MSG = hashWrap512([]byte(_testVectorMessage))
	id.IO.FileName = "<random test message>"
	msg := multiSliceAppendSEP(id.ID.OWNER[:], id.ID.TAG[:], []byte(id.IO.TSS), id.IO.MSG[:])
	id.IO.MSG = blake3fix(msg)
	out("\nLooping hq [sign|verify|integ|unlock|dirMap] operations!")
	out("\nsphincs.sign   : " + sphincsSignBench(id).String() + _OP)
	out("\nsphincs.verify : " + sphincsVerifyBench(id).String() + _OP)
	out("\ncube.tag       : " + cubeTagBench(id).String() + _OP)
	out("\ncube.unlock    : " + cubeUnlockBench(id).String() + _OP)
	// out("\nsign.dirmap    : "+dirmapSignBench().String() + _OP)
	// out("\nverify.dirmap  : "+dirmapVerifyBench().String() + _OP)
	out("............................................................")
	out("total.suite      : " + time.Since(t0).String() + _OP)
	return true
}

// sphingsSignBench ...
func sphincsSignBench(id *HQ) time.Duration {
	t1 := time.Now()
	for i := 0; i < _benchSlow; i++ {
		_ = sphincs.Sign(id.IO.PRIVKEY, id.IO.MSG)
		outPlain("..........")
	}
	return time.Since(t1) / _benchSlow
}

// sphingsVerifyBench ...
func sphincsVerifyBench(id *HQ) time.Duration {
	t1 := time.Now()
	for i := 0; i < _benchFast; i++ {
		_ = sphincs.Verify(id.ID.KEY, id.IO.MSG, id.IO.SIG)
		outPlain(".")
	}
	return time.Since(t1) / _benchFast
}

// cubeTagBench ...
func cubeTagBench(id *HQ) time.Duration {
	t1 := time.Now()
	for i := 0; i < _benchFast; i++ {
		id.genTag()
		outPlain(".")
	}
	return time.Since(t1) / _benchFast
}

// cubeUnlockBench ...
func cubeUnlockBench(id *HQ) time.Duration {
	t1 := time.Now()
	for i := 0; i < _benchSlow; i++ {
		_ = cubetoken.Generate(&cubetoken.Config{
			Progress:     true,
			ForceNoColor: _forceNoColor,
			Memlimit:     _memlimit,
			Layer:        _layer,
			One:          id.IO.HashPassONE,
			Two:          id.IO.HashPassTWO,
			Owner:        hashWrap512(id.ID.OWNER[:]),
			KeyMac:       sha3fix(blake3([]byte(_hashKMAC))),
		})
		outPlain("..........")
	}
	return time.Since(t1) / _benchSlow
}

/*
const _BENCH_TESTDIR         = "/usr/store"

// dirmapSignBench
func dirmapSignBench() time.Duration {
	t1 := time.Now()
	for i := 0; i < _benchSlow; i++ {
		c := new(Config)
		c.FileName = _BENCH_TESTDIR
		c.Silent = true
		_ = DirSign(c)
		outPlain("..........")
	}
	return time.Since(t1) / _benchSlow
}

// dirmapVerifyBench
func dirmapVerifyBench() time.Duration {
	t1 := time.Now()
	for i := 0; i < _benchSlow; i++ {
		c := new(Config)
		c.FileName = _BENCH_TESTDIR
		c.Silent = true
		_ = DirVerify(c)
		outPlain("..........")
	}
	return time.Since(t1) / _benchSlow
}
*/
