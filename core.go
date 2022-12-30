// package hq ...
package hq

// import
import (
	"encoding/base32"
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"syscall"

	"paepcke.de/codereview"
)

// const
const (
	_symlinkBrokenHash = "ac169ead597dac88b2d7223edd85c9895392532cfc7a3c5c29a3fbe3ccba37f2"
	_linefeed          = '\n'
	_linefeedS         = "\n"
	_empty             = ""
	_space             = " "
	_signifyPubExt     = ".signify.pub"
)

// var
var (
	cr = codereview.NewConfigBatch()
)

// codeReviewHash ...
func codeReviewHash(filename string) (bool, []byte) {
	cr.Path = filename
	r := cr.ParseFile()
	return r.Found, r.Result
}

// genTAG ...
func (id *HQ) genTag() {
	s := make([]byte, 64)
	base32.StdEncoding.Encode(s, hashWrap256S(append(id.ID.OWNER[:], id.ID.KEY[:]...)))
	copy(id.ID.TAG[:6], s[:6])
	id.ID.TAG[6] = '-'
	copy(id.ID.TAG[7:9], s[6:8])
	id.ID.TAG[9] = '-'
	copy(id.ID.TAG[10:16], s[8:14])
	id.ID.TAG[16] = '-'
	copy(id.ID.TAG[17:19], s[14:16])
	id.ID.TAG[19] = '-'
	copy(id.ID.TAG[20:], s[16:])
}

// passEntry ...
func (id *HQ) passEntry(reason string) {
	if id.readUnlockedKey(); id.IO.UnlockedKey {
		if _allowUnlockViaEnv {
			return
		}
		errOut("unlocked key found, but function disable via build-time security policy, [enter credentials]")
	}
	if !id.IO.PwdEnv {
		if id.IO.ColorUI {
			bON, cOFF = _Blue, _Off
		}
		repeat := true
		if reason != "create hq identity" {
			repeat = false
			out(bON + "# Please unlock your HQ Identity! [" + reason + "]" + cOFF)
			id.IO.ReportTime = false
			id.report()
		}
		id.IO.HashPassONE = passEntryHash("ONE", true, repeat)
		id.IO.HashPassTWO = passEntryHash("TWO", true, repeat)
		id.IO.ReportTime = true
	}
	if id.IO.HashPassONE == id.IO.HashPassTWO {
		errExit("Password ONE an TWO can not be the same!")
	}
}

// unlockHQ ...
func (id *HQ) unlockHQ() {
	if id.IO.UnlockedKey {
		return
	}
	pubkey := id.ID.KEY
	id.genSphincs()
	switch {
	case id.ID.KEY != pubkey:
		errExit("Passwords do not match, unable to unlock!")
	case id.IO.ColorUI:
		unlock = _Unlock
	}
	out(unlock)
}

//
// PIPE & ENV
//

// isMapOnly ...
func isMapOnly() bool {
	return isEnv(_envHQMapOnly)
}

// isMapClean ...
func isMapClean() bool {
	if isEnv(_envHQMapClean) || _forceMapClean {
		return true
	}
	return false
}

// getKeyStore ...
func getKeyStore() string {
	keystore, err := os.UserHomeDir()
	if err != nil {
		errExit("unable find homedirectory")
	}
	return keystore + "/.hq/"
}

// getOwnerEnv ...
func getOwnerEnv() string {
	own, ok := syscall.Getenv(_envHQOWNER)
	if !ok {
		return _empty
	}
	l := len(own)
	if l < 6 || l > 64 {
		errExit(_errOwnerSize)
	}
	if strings.Contains(own, "=") {
		errExit(_errOwnerCharacter)
	}
	return own
}

//
// FILE IO
//

// writeSig ...
func (id *HQ) writeSig() {
	ext, prefix := _extSignature, []byte("#HQS#@@@@@@")
	sig := id.IO.SIG[:]
	if id.IO.IsExec {
		s := matchShebang(id.IO.TokenExec)
		id.IO.TokenExec = s.token
		if len(id.IO.TokenExec) != 6 {
			errExit("unkown TokenExec")
		}
		ext, prefix = _extExecutable, []byte("#HQX#"+id.IO.TokenExec)
		sig = append(sig, id.IO.SCRIPT...)
		id.IO.FileName = id.IO.FileName[:len(id.IO.FileName)-id.IO.ScriptExtL]
	}
	sig = []byte(base64.StdEncoding.EncodeToString(sig))
	sig = multiSliceAppendSEP([]byte(_sheBang), prefix, id.ID.TAG[:], []byte(id.IO.TSS), sig)
	if err := os.WriteFile(id.IO.FileName+ext, sig, 0o770); err != nil {
		errExit("unable to write signature :" + id.IO.FileName + ext)
	}
	if id.IO.SIGNIFYFILE != nil {
		if err := os.WriteFile(id.IO.FileName+_extSignify, id.IO.SIGNIFYFILE, 0o770); err != nil {
			errExit("unable to write signify sig :" + id.IO.FileName + _extSignify)
		}
	}
}

// parseSig ...
func (id *HQ) parseSig(c *Config) {
	var err error
	filesig := id.getSig(c)
	switch string(filesig[16:19]) {
	case "HQS":
	case "HQX":
		id.IO.IsExec = true
		s := matchShebang(string(filesig[20:26]))
		id.IO.TokenExec = s.token
	default:
		errExit("defective .hqs/.hqx file or pipe container")
	}
	id.readPublicKey(string(filesig[27:57]))
	id.IO.TSS = string(filesig[58:68])
	if _, err = strconv.ParseInt(string(id.IO.TSS), 10, 0); err != nil {
		errExit("unable to parse timestamp")
	}
	if filesig, err = base64.StdEncoding.DecodeString(string(filesig[69 : len(filesig)-1])); err != nil {
		errExit("signature base64 decode error")
	}
	copy(id.IO.SIG[:], filesig)
	switch {
	case id.IO.IsExec:
		id.IO.SCRIPT = filesig[41000:]
	default:
		id.IO.MSG = getMSGHash(id.IO.FileName[:len(id.IO.FileName)-4])
	}
}

// getSig ...
func (id *HQ) getSig(c *Config) []byte {
	if c.IsPipe {
		return []byte(getPipe())
	}
	return readFileErrExit(id.IO.FileName)
}

// writePublicKey ...
func (id *HQ) writePublicKey() {
	keystore := getKeyStore()
	if err := os.MkdirAll(keystore[:len(keystore)-1], 0o664); err != nil {
		errExit("unable to create" + keystore)
	}
	filename := keystore + string(id.ID.TAG[:])
	key := append(id.ID.OWNER[:], []byte(base64.StdEncoding.EncodeToString(id.ID.KEY[:]))...)
	writeFileErrExit(filename, key, 0o440)
	if id.IO.SetMe {
		_ = os.Remove(keystore + "me")
		if err := os.Symlink(filename, keystore+"me"); err != nil {
			errExit("unable to set me tag symbolic link [" + keystore + "me]")
		}
	}
	if id.IO.SIGNIFYPUB != nil {
		writeFileErrExit(filename+_signifyPubExt, id.IO.SIGNIFYPUB, 0o440)
	}
}

// writeUnlockedKey ...
func (id *HQ) writeUnlockedKey() {
	keystore := getKeyStore()
	if err := os.MkdirAll(keystore[:len(keystore)-1], 0o600); err != nil {
		errExit("unable to create" + keystore)
	}
	filename := keystore + ".unlocked/" + string(id.ID.TAG[:])
	writeFileErrExit(filename, []byte(base64.StdEncoding.EncodeToString(id.IO.PRIVKEY[:])), 0o400)
}

// wipeUnlockedKey ...
func (id *HQ) wipeUnlockedKey() bool {
	keystore := getKeyStore()
	filename := keystore + ".unlocked/" + string(id.ID.TAG[:])
	var blind [1452]byte
	for i := range blind {
		blind[i] = '0' // simply zero-out, assume non-permanent, non-journaled,  memory-backend storage backend [eg. tmpfs]
	}
	writeFileErrExit(filename, blind[:], 0o660)
	os.Remove(filename)
	id.readUnlockedKey()
	if !id.IO.UnlockedKey {
		if id.IO.ColorUI {
			lock = _Lock
		}
		out(lock)
		return true
	}
	errOut("Unlocked key removal failed!")
	return false
}

// readUnlockedKey ...
func (id *HQ) readUnlockedKey() {
	id.IO.UnlockedKey = false
	keystore := getKeyStore()
	filename := keystore + ".unlocked/" + string(id.ID.TAG[:])
	key, err := os.ReadFile(filename)
	if err != nil {
		return
	}
	s, err := base64.StdEncoding.DecodeString(string(key))
	if err != nil {
		errOut("unable to decode unlocked key [" + filename + "]")
		return
	}
	copy(id.IO.PRIVKEY[:], []byte(s))
	id.IO.UnlockedKey = true
}

// readPublicKey ...
func (id *HQ) readPublicKey(nametag string) {
	var (
		err    error
		key, k []byte
	)
	keystore := getKeyStore()
	if nametag == "me" {
		nametag, err = os.Readlink(keystore + "me")
		if err != nil {
			nametag = "me"
		}
	}
	if len(nametag) > 30 {
		nametag = nametag[len(nametag)-30:]
	}
	key = readFileErrExit(keystore + nametag)
	copy(id.ID.OWNER[:], key)
	if k, err = base64.StdEncoding.DecodeString(string(key[64:])); err != nil {
		errExit("unable to decode key, base64 key part is defect" + keystore + string(id.ID.TAG[:]))
	}
	copy(id.ID.KEY[:], k)
	id.genTag()
	if nametag != "me" {
		if string(id.ID.TAG[:]) != nametag {
			errExit("key integrity problem, tag checksum missmatch")
		}
	}
}

// getMap
func (c *Config) getMap() string {
	var curr string
	dir := readDir(c.FileName)
	offset, term, name := 0, ".hqMAP.", ""
	if c.TargetTS != "" {
		offset = len(c.TargetTS)
		term += c.TargetTS
	}
	for _, entry := range dir {
		name = entry.Name()
		if len(name) == 42 {
			if name[:7+offset] == term && name[38:] == _compressedFileExt && !entry.IsDir() {
				curr = name
			}
		}
	}
	switch {
	case curr == "" && !c.Silent:
		errExit("unable to find a .hqMAP [" + term + "]")
	case curr == "":
		return ""
	case c.FileName == ".":
		return curr
	}
	return c.FileName + "/" + curr
}

// pwdTarget
func (id *HQ) pwdTarget(c *Config) {
	if len(os.Args) > 2 {
		c.PwdService = os.Args[2]
		l := len(c.PwdService)
		if l != 0 {
			if l > 4 || l < 256 {
				id.IO.MSG = hashWrap512([]byte(c.PwdService))
				return
			}
			errExit("The pwd and lpwd option need to specify an <target> must be more than 4 & less than 256 characters!")
			return
		}
	}
	errExit("The pwd and lpwd option need to specify an <target> to generate an password, example:: hq pwd gmail.com")
}

// cleanMapFiles ...
func cleanMapFiles(path string) {
	list := readDir(path)
	for _, filename := range list {
		name := filename.Name()
		switch {
		case name[0] != '.':
			return // fail early, fail cheap [its a sorted list]
		case name[1] != 'h':
			continue
		case len(name) < 39:
			continue
		case name[:6] == ".hqMAP":
			syscall.Unlink(path + "/" + name)
		}
	}
}
