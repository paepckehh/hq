// package hq ...
package hq

// import
import (
	"strconv"
	"strings"
	"time"
)

// const
const (
	_testVectorMsg     = "<random test message>"
	_testVectorTag     = "TIES25-DE-NIIOAS-SO-F42EMA6WOW"
	_testVectorOwner   = "potus@wh.gov"
	_testVectorMessage = "The brown fox jumps over the green flower!"
	_testVectorPassOne = "Nachts sind fast alle blauen Katzen grau-blau-gruen!"
	_testVectorPassTwo = "WTH !? Never Ever look at test vector data sources ... Never! NEVER! ###"
	_testVectorSignify = "RWSEUmAz8hOAqdcBhnrEmLoEFREXbV/qHoMCYqHP4Z+AZ6ZD3Ffl1DRr"
)

// cryptoVerify ...
func (c *Config) cryptoVerify() bool {
	id := NewHQ(c)
	id.ID.OWNER = pad(_testVectorOwner)
	id.IO.HashPassONE = hashWrap512([]byte(_testVectorPassOne))
	id.IO.HashPassTWO = hashWrap512([]byte(_testVectorPassTwo))
	id.IO.TSS = strconv.FormatInt(id.IO.Start.Unix(), 10)
	out("\nTEST VECTOR: [g]enerate & [u]nlock hq identity! [nameTag = mac integ checksum] and generate signify legacy keypair!")
	id.IO.Signify = true
	id.IO.SIGNIFYMSG = []byte(_testVectorMsg)
	id.IO.Start = time.Now()
	id.genSphincs()
	out(yON + "\n[ " + cOFF + "generate" + yON + " ]" + cOFF)
	id.report()
	if id.IO.ColorUI {
		gON, yON, cOFF = _Green, _Yelllow, _Off
		valid, fail = _Valid, _Fail
	}
	signifyState := fail + _space
	sig := strings.Split(string(id.IO.SIGNIFYPUB), _linefeedS)
	if sig[1] == _testVectorSignify {
		signifyState = valid + _space
	}
	ok, tag := false, fail+_space
	if string(id.ID.TAG[:]) == _testVectorTag {
		ok, tag = true, valid+_space
	}
	out(yON + "HQ Name TAG     : " + tag + bON + _testVectorTag + cOFF)
	out(yON + "SignifyPubKey   : " + signifyState + bON + sig[1] + cOFF)
	out("\nTEST VECTOR: [s]ign & [v]erify message via hq sphincs and legacy signify signatures!")
	id.IO.TSS = strconv.FormatInt(id.IO.Start.Unix(), 10)
	id.IO.MSG = hashWrap512([]byte(_testVectorMessage))
	id.IO.FileName = _testVectorMsg
	out(yON + "\n[ " + cOFF + "sign" + yON + " ]" + cOFF)
	id.IO.End = time.Time{}
	id.IO.Start = time.Now()
	id.genSig()
	id.report()
	out(yON + "\n[ " + cOFF + "verify" + yON + " ]" + cOFF)
	id.IO.MSG = hashWrap512([]byte(_testVectorMessage))
	id.IO.End = time.Time{}
	id.IO.Start = time.Now()
	if id.validateSig() {
		id.IO.ReportValid = true
		id.report()
		outPlain(yON + "Status         : " + valid)
	} else {
		id.IO.ReportValid = false
		id.report()
		outPlain(yON + "Status         : " + fail)
		ok = false
	}
	if ok {
		out(gON + "\n\nCryptographic hq internal library status is valid!" + cOFF)
		return true
	}
	out(aON + "\n\nCryptographic hq internal library validation failed!" + cOFF)
	return false
}
