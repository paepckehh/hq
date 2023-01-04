package hq

import (
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
)

var (
	// dynamic build time linker config
	_semver    = "0.0.0"
	_commit    = "GITCOMMIT"
	_builddate = "BUILDDATE"
)

const (
	_pipe   = "<input from pipe>"
	_valid  = "[CONFIRMED]"
	_fail   = "[FAIL]"
	_lock   = "# HQ IDENTIY SUCCESSFULLY [SECURED|LOCKED]"
	_unlock = "# HQ IDENTIY SUCCESSFULLY UNLOCKED!"

	_owner     = "# Owner ID      : "
	_tag       = "# Name TAG      : "
	_signifyid = "# SignifyPubKey : "
	_file      = "# File Name     : "
	_ts        = "# Time Stamp    : "
	_total     = "# Time needed   : "
	_ffail     = "# Files FAIL    : "
	_fok       = "# Files OK      : "
	_fnew      = "# Files NEW     : "
	_files     = "# Files Total   : "
	_stat      = "# Status        : "
	_errc      = "# Error Code    : "
	_exp       = "# File Expected : "
	_calc      = "# File Found    : "
	_cexp      = "# Code Expected : "
	_ccalc     = "# Code Found    : "

	_errFileAccess     = "UNABLE TO READ FILE"
	_errFilePermission = "UNABLE TO READ FILE [ACCES:PERMISSION]"
	_errFileNotExist   = "FILE REMOVED"
	_errFileChecksum   = "FILE MODIFIED [FILE HASH MISSMATCH]"
	_errChashOK        = "COMPILED CODE WILL BE OK [CODEREVIEW HASH NOT CHANGED]"
	_errChashFail      = "CODE MODIFIED [CODEREVIEW HASH MISSMATCH]"
	_errChashUnable    = "UNABLE TO VERIFY SIGNED CODE HASH"
	_errIntParser      = "HQ INTERAL PARSER ERROR: UNKNOWN OPTION"
	_errOwnerSize      = "no support for UserIDs with less than 6 or more than 64 characters"
	_errOwnerCharacter = "no support for UserIDs with the equal sign (=)"
)

func version() {
	out("hq ( VERSION: " + _semver + " )" + " ( COMMIT: " + _commit + " )" + " ( BUILD DATE: " + _builddate + " )")
}

func syntaxUI() {
	out("usage: hq  <action> <opt:target> <opt:timestamp|exec-parameter>")
}

func usage() {
	out("\naction:")
	out("[s]ign      sign mode for <target>")
	out("[c]ode      sign mode for <target>, include additional code-review hashes")
	out("[v]erify    verify mode for <target>")
	out("[r]un       run .hqx exec container")
	out("[g]enerate  generate new hq id [or: re-produce public key]")
	out("[u]nlock    unlock id [raw sphincs key]")
	out("[l]ock      lock [remove] cached raw sphincs key")
	out("[p]wd       generate hq id and <target> specific password")
	out("[x]pwd      generate hq id and <target> specific legacy password")
	out("[t]est      verify crypto functions via hard-wired test vector suite")
	out("[b]ench     benchmark")
	out("[h]elp      show help\n")
	out("<hqx>|<hqs>|<dir>|<pipe>|<exec> - object typ will pick the action\n")
}

func examples() {
	out("EXAMPLES")
	out(" hq generate [generate new hq identity]")
	out(" hq sign mybackup.tar.zst")
	out(" hq verify mybackup.tar.zst.hqs")
	out(" hq mybackup.tar.zst.hqs")
	out(" hq sign myscript.sh [.sh -> .hqx]")
	out(" hq verify myscript.hqx [display script content]")
	out(" hq run myscript.hqx")
	out(" hq myscript.hqx")
	out(" ./myscript.hqx")
	out(" cat myscript.hqx | hq")
	out(" hq myscript.sh  [run myscript.sh]")
	out(" hq v . 1633 [verify most recent hqMAP starting 1633* ]")
	out(" hq  sign /usr/store")
	out(" hq  s . [short form for sign map in current dir]")
	out(" hq  v [verify most recent .hqMAP in . ]\n")
	out(" ./myfile.hqs [verify signature of myfile]\n")
}

func env() {
	out("ENV")
	out(" FORCE_COLOR=true          color terminal output")
	out(" " + _envHQSignify + "=true       generate additional OpenBSD signify compatible .sig signatures")
	out(" " + _envHQSigOnly + "=true          to sign executeables as normal .hqs signatures only")
	out(" " + _envHQMapOnly + "=true          to generate .hqMAP files without signature")
	out(" " + _envHQMapClean + "=true         to remove all existing .hqMAP[s] on <target>")
	out(" " + _envHQOWNER + "                  set owner for generate operations [batch mode]\n")
	out(" [-> all env settings can be [disabled|overruled] via compile time flags!\n")
}

func help() {
	// version()
	syntaxUI()
	usage()
	env()
	examples()
}

func (id *HQ) reportPwd(c *Config) {
	if id.IO.ColorUI {
		gON, yON, cOFF = _Green, _Yelllow, _Off
	}
	defer outPlain(cOFF)
	outPlain(yON + "# PASSWORD FOR SERVICE : " + c.PwdService)
	if c.PwdComplex {
		pwd := argon2d(id.IO.SIG[8192:], sha2(append([]byte(_hashKMAC), id.IO.SIG[:8192]...)))
		out(" -> " + gON + base64.StdEncoding.EncodeToString(sha3(sha2(pwd)))[:32])
		return
	}
	pwd := argon2d(id.IO.SIG[4096:], sha2(append([]byte(_hashKMAC), id.IO.SIG[:4096]...)))
	out(" [legacy mode] -> " + gON + base64.StdEncoding.EncodeToString(sha2(sha3(pwd)))[:16])
}

func (id *HQ) reportDir() {
	if id.IO.Silent {
		return
	}
	if id.IO.ReportValid {
		add = _valid
		if id.IO.ColorUI {
			add = _Valid
		}
	}
	if id.IO.ColorUI {
		aON, rON, bON, gON, eON, cOFF = _Red, _Red, _Blue, _Green, _Grey, _Off
		files, ffail, fok, total = _Files, _Ffail, _Fok, _Total
		defer outPlain(cOFF)
		if id.IO.FilesFail == 0 {
			aON = _Green
		}
	}
	if id.IO.FilesNew != 0 {
		switch {
		case id.IO.FilesNew > 2:
			out("\n" + fnew + rON + strconv.FormatUint(id.IO.FilesNew, 10) + cOFF)
		default:
			out("\n" + fnew + gON + strconv.FormatUint(id.IO.FilesNew, 10) + cOFF)
		}
	}
	out(ffail + aON + strconv.FormatUint(id.IO.FilesFail, 10) + cOFF)
	out(fok + gON + padstring(strconv.FormatUint(id.IO.FilesTotal-id.IO.FilesFail, 10)) + cOFF + add)
	out(files + bON + strconv.FormatUint(id.IO.FilesTotal, 10) + cOFF)
	out(total + eON + time.Since(id.IO.Start).String() + cOFF)
}

func (id *HQ) report() {
	if id.IO.Silent {
		return
	}
	if id.IO.ColorUI {
		bON, cON, mON, wON, rON, cOFF = _Blue, _Cyan, _Magenta, _White, _Grey, _Off
		owner, tag, signifyid, total, ts, file = _Owner, _Tag, _Signifyid, _Total, _Ts, _File
		defer outPlain(cOFF)
	}
	if id.IO.ReportValid {
		add = _valid
		if id.IO.ColorUI {
			add = _Valid
		}
	}
	if id.IO.ReportID {
		out(owner + cON + unpad(id.ID.OWNER) + cOFF)
		out(tag + mON + padstring(string(id.ID.TAG[:])) + cOFF + add)
		if id.IO.SIGNIFYPUB != nil {
			sig := strings.Split(string(id.IO.SIGNIFYPUB), _linefeedS)
			out(signifyid + mON + padstring(sig[1]+cOFF))
		}
	}
	if id.IO.FileName != "" && id.IO.FileName != "." {
		out(file + bON + padstring(id.IO.FileName) + cOFF + add)
	}
	if id.IO.TSS != "" {
		out(ts + wON + padstring(unix2RFC850(id.IO.TSS)+" ["+id.IO.TSS+"]") + add)
	}
	if id.IO.ReportTime && _reportTime {
		if id.IO.End.IsZero() {
			id.IO.End = time.Now()
		}
		out(total + rON + id.IO.End.Sub(id.IO.Start).String() + cOFF)
	}
}

func getOwner() [64]byte {
	var o string
	if o = getOwnerEnv(); o == "" {
		if getColorUI() {
			owner, cOFF = _Owner+_Cyan, _Off
			defer outPlain(cOFF)
		}
		for {
			o = readLine(owner)
			outPlain(cOFF)
			l := len(o)
			switch {
			case l < 6 || l > 64:
				errOut(_errOwnerSize)
				continue
			case strings.Contains(o, "="):
				errOut(_errOwnerCharacter)
				continue
			}
			break
		}
	}
	return pad(o)
}

func passEntryHash(name string, masked, repeat bool) [64]byte {
	if getColorUI() {
		bON, cOFF = _Blue, _Off
		defer outPlain(cOFF)
	}
	for {
		p := readPassword(bON+"# Passphrase "+name+": ", masked)
		outPlain(cOFF)
		switch {
		case len(p) < _minimumPasswordLen:
			out("  Please enter a Passphrase with at least " + strconv.Itoa(_minimumPasswordLen) + " characters")
			continue
		case repeat:
			p2 := readPassword(bON+"# Repeat     "+name+": ", masked)
			outPlain(cOFF)
			if p != p2 {
				out("  Passwords do not match! Please try again!")
				continue
			}
		}
		return hashWrap512([]byte(p))
	}
}

func errOut(m string) {
	if getColorUI() {
		aON, cOFF = _Red, _Off
	}
	out(aON + "ERROR: " + m + cOFF)
}

func errExit(m string) {
	errOut(m)
	os.Exit(1)
}

func errsyntax(m string) {
	if m != "" {
		if getColorUI() {
			aON, cOFF = _Red, _Off
		}
		out(aON + "ERROR: " + m + cOFF)
	}
	syntaxUI()
	usage()
	version()
	os.Exit(1)
}

//
// COLOR UI SECTION
//

const (
	_envNoColor = "NO_COLOR"
	// basic ansi terminal color definitions
	_Off     = "\033[0m"
	_Grey    = "\033[0m"
	_Red     = "\033[1;91m"
	_Green   = "\033[2;92m"
	_Yelllow = "\033[2;93m"
	_Blue    = "\033[2;94m"
	_Magenta = "\033[2;95m"
	_Cyan    = "\033[2;96m"
	_White   = "\033[2;97m"

	// ui defaults
	_Valid     = _Green + _valid + _Off
	_Fail      = _Red + _fail + _Off
	_Lock      = _Green + _lock + _Off
	_Unlock    = _Green + _unlock + _Off
	_Total     = _Yelllow + _total + _Off
	_Owner     = _Yelllow + _owner + _Off
	_Signifyid = _Yelllow + _signifyid + _Off
	_Tag       = _Yelllow + _tag + _Off
	_File      = _Yelllow + _file + _Off
	_Ts        = _Yelllow + _ts + _Off
	_Stat      = _Yelllow + _stat + _Off
	_Ffail     = _Yelllow + _ffail + _Off
	_Fok       = _Yelllow + _fok + _Off
	_Fnew      = _Yelllow + _fnew + _Off
	_Files     = _Yelllow + _files + _Off
	_Errc      = _Yelllow + _errc + _Off
	_Exp       = _Yelllow + _exp + _Off
	_Calc      = _Yelllow + _calc + _Off
	_Cexp      = _Yelllow + _cexp + _Off
	_Ccalc     = _Yelllow + _ccalc + _Off
)

var (
	add, signifyid                                        = "", _signifyid
	cOFF, aON, bON, cON, gON, eON, rON, mON, wON, yON     = "", "", "", "", "", "", "", "", "", ""
	files, file, fail, ffail, fok, fnew, owner, ts, valid = _files, _file, _fail, _ffail, _fok, _fnew, _owner, _ts, _valid
	errc, exp, calc, cexp, ccalc                          = _errc, _exp, _calc, _cexp, _ccalc
	total, tag, stat, unlock, lock                        = _total, _tag, _stat, _unlock, _lock
)

func getColorUI() bool {
	if _forceNoColor {
		return false
	}
	if _, ok := syscall.Getenv(_envNoColor); ok {
		return false
	}
	return true
}

//
// LITTLE HELPER
//

func argon2d(p, s []byte) []byte {
	return argon2.Key(p, s, 5, uint32(_memlimit), uint8(_parallel), 512)
}
