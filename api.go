// Package hq implements sphincs-blake3-512 hypertree signatures
package hq

import (
	"os"
	"runtime"
	"strconv"
	"time"

	"paepcke.de/sphincs"
)

//
// EXPORTED STRUCTS
//

// const
const (
	// PublicKeySize
	PublicKeySize = sphincs.PublicKeySize
	// PrivateKeySize
	PrivateKeySize = sphincs.PrivateKeySize
	// SignatureSize
	SignatureSize = sphincs.SignatureSize
	// HashSize
	HashSize = 64
)

// HQ ...
type HQ struct {
	// ID identiy
	ID
	// IO exchange
	IO
}

// ID identiy
type ID struct {
	OWNER [HashSize]byte      // OWNER ID
	TAG   [30]byte            // NAME TAG
	KEY   [PublicKeySize]byte // SPHINCS Public Key
}

// IO exchange
type IO struct {
	HashPassONE     [HashSize]byte       // hashed password token
	HashPassTWO     [HashSize]byte       // hashed password token
	MSG             [HashSize]byte       // message[hash] to [sign|verify]
	MSGRAW          []byte               // pointer to raw message
	SCRIPT          []byte               // compressed and base64 encoded exec
	TokenExec       string               // magic token to determine exec type for execution
	ScriptExtL      int                  // lengh of extension name
	DirName         string               // Report DirName
	FileName        string               // Report FileName
	FilesTotal      uint64               // total number of files
	FilesFail       uint64               // total number of files with hash|checksum errors
	FilesNew        uint64               // total number of files with hash|checksum errors
	Signify         bool                 // enable optional OpenBSD signify signatures
	PlainTextScript bool                 // Plain Text Posix script interp mode
	MapClean        bool                 // true if we need to wipe old maps
	Silent          bool                 // silent mode for benchmarking
	UnlockedKey     bool                 // true if /.hq/.unlocked key was found
	IsExec          bool                 // true if exec mode
	ReportID        bool                 // Report Status [summary]
	ReportTime      bool                 // Report Status [summary]
	ReportValid     bool                 // Report Status [summary]
	ColorUI         bool                 // enable CLI ColorUI
	SetMe           bool                 // Set Me Key Symbolic Link
	PwdEnv          bool                 // true if pass creds from env
	CPU             int                  // number of CPU cores
	Start           time.Time            // Time Stamp Start Action
	End             time.Time            // Time Stamp End Action
	TSS             string               // POSIX TS (nanoseconds since 01/01/1970 00:00 UTC)
	SIG             [SignatureSize]byte  // RAW SPHINCS-256 signature
	PRIVKEY         [PrivateKeySize]byte // RAW SPHINCS-256 private key
	SIGNIFYMSG      []byte               // Encoded OpenBSD Signify Message
	SIGNIFYPUB      []byte               // Encoded OpenBSD Signify PublicKey
	SIGNIFYFILE     []byte               // Encoded OpenBSD Signify Signature
}

// Config ...
type Config struct {
	Action          string   // Requested Action [sign|verify|generate|bench]
	Target          string   // Requested Target [dir|file]
	TargetTS        string   // Requested Target TimeStamp
	FileName        string   // FileName
	File            *os.File // FileHandle
	Signify         bool     // enable optional OpenBSD signify signatures
	CodeReview      bool     // enable additional code-review hashes for source code files
	Silent          bool     // enable silent mode [eg. for benchmarking]
	IsExec          bool     // true if executeable mode is detected
	IsPipe          bool     // true if exec mode is detected
	MapOnly         bool     // true if exec mode is detected
	RunExec         bool     // true if run mode [not display mode] is requested
	PwdComplex      bool     // true if complex legacy password is requested
	PlainTextScript bool     // run plaintext sh script interpreter
	TokenExec       string   // magic token to determine exec type for execution
	PwdService      string   // the [legacy] password service name [psn]
	ScriptExtL      int      // lengh of extension name
}

//
// EXPORTED STRUCTS DEFAULTS
//

// NewHQ ...
func NewHQ(c *Config) *HQ {
	return &HQ{
		ID{},
		IO{
			Start:       time.Now(),
			ColorUI:     getColorUI(),
			ReportID:    true,
			ReportValid: false,
			ReportTime:  true,
			CPU:         runtime.NumCPU(),
			Signify:     c.Signify,
		},
	}
}

// NewConfig ...
func NewConfig() *Config {
	return &Config{
		MapOnly:    isMapOnly(),
		IsPipe:     isPipe(),
		FileName:   ".",
		Target:     "file",
		PwdComplex: true,
		Signify:    isEnv(_envHQSignify),
	}
}

//
// EXPORTED FUNCTIONS
//

// ParseCmd ...
func (c *Config) ParseCmd() { c.parseCmd() }

// RunAction ...
func (c *Config) RunAction() bool { return c.runAction() }

// DirVerify ...
func (c *Config) DirVerify() bool { return c.dirVerify() }

// DirSign ...
func (c *Config) DirSign() bool { return c.dirSign() }

// CryptoVerify ...
func (c *Config) CryptoVerify() bool { return c.cryptoVerify() }

// RunExecPlain ...
func (c *Config) RunExecPlain() bool { return c.runExecPlain() }

// Bench ...
func (c *Config) Bench() bool { return c.bench() }

// Generate sphincs keypair
func (c *Config) Generate() bool {
	id := NewHQ(c)
	id.IO.SetMe = true
	id.ID.OWNER = getOwner()
	id.passEntry("create hq identity")
	id.IO.Start = time.Now()
	id.genSphincs()
	id.writePublicKey()
	id.report()
	return true
}

// FileSign ...
func (c *Config) FileSign() bool {
	id := NewHQ(c)
	id.IO.TSS = strconv.FormatInt(id.IO.Start.Unix(), 10)
	id.IO.FileName = c.FileName
	id.IO.ScriptExtL = c.ScriptExtL
	chanHash := make(chan [HashSize]byte, 1)
	go func() {
		chanHash <- getMSGHash(id.IO.FileName)
		close(chanHash)
	}()
	id.readPublicKey(_me)
	id.passEntry("pending " + c.Target + " sign operation [" + id.IO.FileName + "]")
	id.IO.MSG = <-chanHash
	id.IO.Start = time.Now()
	id.unlockHQ()
	id.genSig()
	id.writeSig()
	id.report()
	return true
}

// FileSignExecuteable ...
func (c *Config) FileSignExecuteable() bool {
	id := NewHQ(c)
	id.IO.TSS = strconv.FormatInt(id.IO.Start.Unix(), 10)
	id.IO.FileName = c.FileName
	id.IO.ScriptExtL = c.ScriptExtL
	id.IO.IsExec = true
	id.IO.TokenExec = c.TokenExec
	id.IO.SCRIPT = compressZstd(readFileErrExit(id.IO.FileName), _compressedScriptLevel)
	id.readPublicKey(_me)
	id.passEntry("pending " + c.Target + " sign operation [" + id.IO.FileName + "]")
	id.IO.Start = time.Now()
	id.unlockHQ()
	id.genSig()
	id.writeSig()
	id.report()
	return true
}

// FileVerify ...
func (c *Config) FileVerify() bool {
	id := NewHQ(c)
	id.IO.FileName = c.FileName
	id.IO.ReportValid = false
	id.parseSig(c)
	if id.validateSig() {
		id.IO.ReportValid = true
		id.report()
		return true
	}
	id.report()
	if id.IO.ColorUI {
		stat, fail = _Stat, _Fail
	}
	out(stat + "SIGNATURE VALIDATION: " + fail)
	return false
}

// FileVerifyExecuteable verifies and executes an hq singed hqx container
func (c *Config) FileVerifyExecuteable() bool {
	id := NewHQ(c)
	id.IO.FileName = c.FileName
	id.IO.IsExec = c.IsExec
	id.IO.ReportValid = false
	id.parseSig(c)
	if id.validateSig() {
		id.IO.ReportValid = true
		id.report()
		if c.RunExec {
			return id.runExec()
		}
		out(string(decompressZstd(id.IO.SCRIPT)))
		return true
	}
	id.report()
	if id.IO.ColorUI {
		stat, fail = _Stat, _Fail
	}
	out(stat + "SIGNATURE VALIDATION: " + fail)
	return false
}

// Unlock unlocks the raw sphincs key for subsequent batch operations
func (c *Config) Unlock() bool {
	if !_allowUnlockViaEnv {
		errExit("store unlocked key operations disabled by security policy")
	}
	id := NewHQ(c)
	id.readPublicKey(_me)
	id.passEntry("pending unlock operation")
	switch {
	case id.validateKey():
		id.report()
		return true
	case !id.wipeUnlockedKey():
		errExit("unable to [write|delete] key to ~/hq/.unlocked")
	}
	id.IO.Start = time.Now()
	id.unlockHQ()
	id.genSig()
	id.writeUnlockedKey()
	id.report()
	return true
}

// Lock cleans the Unlock() exposed raw key
func (c *Config) Lock() bool {
	if !_allowUnlockViaEnv {
		errExit("store unlocked key operations disabled by security policy")
	}
	id := NewHQ(c)
	id.readPublicKey(_me)
	id.report()
	id.IO.Start = time.Now()
	return id.wipeUnlockedKey()
}

// LegacyPass is a [k]ey[d]erivation[f]unction for legacy passwords
func (c *Config) LegacyPass() bool {
	id := NewHQ(c)
	id.pwdTarget(c)
	id.readPublicKey(_me)
	id.passEntry("legacy password [generation|reproduction]")
	id.IO.Start = time.Now()
	id.unlockHQ()
	id.genSig()
	id.report()
	id.IO.Start = time.Now()
	id.reportPwd(c)
	id.IO.End = time.Time{}
	id.IO.ReportID = false
	id.IO.ReportTime = true
	id.report()
	return true
}
