package hq

import (
	"strconv"
	"strings"
	"time"

	"paepcke.de/hq/cubetoken"
	"paepcke.de/signify"
	"paepcke.de/sphincs"
)

const (
	_signifyOffset = 12
	_hqid          = " [HQID:"
	_timeStamp     = " [TS:"
	_closebracket  = "]"
)

// genSPHINCS ...
func (id *HQ) genSphincs() {
	// generate private key seeds
	seed := cubetoken.Generate(&cubetoken.Config{
		Progress:     true,
		ForceNoColor: _forceNoColor,
		Memlimit:     _memlimit,
		Parallel:     _parallel,
		Layer:        _layer,
		One:          id.IO.HashPassONE,
		Two:          id.IO.HashPassTWO,
		Owner:        hashWrap512(id.ID.OWNER[:]),
		KeyMac:       sha3fix(blake3([]byte(_hashKMAC))),
	})

	// generate sphincs keyset
	id.ID.KEY, id.IO.PRIVKEY = sphincs.GenerateKey(seed.SphincsSeed)

	// validate keys via test msg sign/validate
	msg := blake3fix([]byte("NACHTS SIND ALLE BLAUEN KATZEN GRAU"))
	sig := sphincs.Sign(id.IO.PRIVKEY, msg)
	if !sphincs.Verify(id.ID.KEY, msg, sig) {
		errExit("generate: sphincs keyset validation check failed")
	}

	// generate nametag
	id.genTag()

	// generate signify keyset
	if id.IO.Signify {
		var err error
		var c strings.Builder
		c.WriteString(_hqid)
		c.Write(id.ID.TAG[:])
		c.WriteString(_closebracket)
		id.IO.SIGNIFYPUB, err = signify.GeneratePKFromSeed(seed.SignifySeed).GetPubKeyFile(c.String())
		if err != nil {
			errExit("gen signify private key: " + err.Error())
		}
	}
}

// genSIG ...
func (id *HQ) genSig() {
	var err error
	msg := multiSliceAppendSEP(id.ID.OWNER[:], id.ID.TAG[:], []byte(id.IO.TSS), id.IO.MSG[:])
	if id.IO.IsExec {
		msg = append(msg, id.IO.SCRIPT...)
	}
	id.IO.MSG = blake3fix(msg)
	id.IO.SIG = sphincs.Sign(id.IO.PRIVKEY, id.IO.MSG)
	if id.IO.Signify {
		seed := setLast40(hashWrap512(id.IO.PRIVKEY[_signifyOffset:]))
		s := signify.NewMessage()
		var c strings.Builder
		c.WriteString(_hqid)
		c.Write(id.ID.TAG[:])
		c.WriteString(_closebracket)
		c.WriteString(_space)
		c.WriteString(_timeStamp)
		c.WriteString(strconv.Itoa(int(time.Now().Unix())))
		c.WriteString(_closebracket)
		s.UntrustedComment = c.String()
		if id.IO.SIGNIFYMSG != nil {
			s.Raw = id.IO.SIGNIFYMSG
		} else {
			s.Raw = readFileErrExit(id.IO.FileName)
		}
		if id.IO.SIGNIFYFILE, err = s.GetSigFile(signify.GeneratePKFromSeed(seed)); err != nil {
			errExit("sign: signify: " + err.Error())
		}
	}
}

// validateSig ...
func (id *HQ) validateSig() bool {
	msg := multiSliceAppendSEP(id.ID.OWNER[:], id.ID.TAG[:], []byte(id.IO.TSS), id.IO.MSG[:])
	if id.IO.IsExec {
		msg = append(msg, id.IO.SCRIPT...)
	}
	id.IO.MSG = blake3fix(msg)
	return sphincs.Verify(id.ID.KEY, id.IO.MSG, id.IO.SIG)
}

// validateKEY ...
func (id *HQ) validateKey() bool {
	msg := blake3fix([]byte("NACHTS SIND ALLE BLAUEN KATZEN GRAU"))
	sig := sphincs.Sign(id.IO.PRIVKEY, msg)
	return sphincs.Verify(id.ID.KEY, msg, sig)
}

// setLast40 ...
func setLast40(in [64]byte) (r [40]byte) {
	for i := 0; i < 40; i++ {
		r[i] = in[64-49+i]
	}
	return r
}
