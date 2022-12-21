// package hq
package hq

// import
import (
	"io"
	"os"
	"sync"
	"time"
)

// dirVerify
func (c *Config) dirVerify() bool {
	id := NewHQ(c)
	id.IO.DirName = c.FileName
	id.IO.ReportValid = true
	id.IO.FileName = c.getMap()
	id.IO.FileName += _extSignature
	id.IO.Silent = c.Silent
	var waitTotals sync.WaitGroup
	waitTotals.Add(1)
	go func() {
		id.IO.FilesTotal, id.IO.FilesFail, id.IO.FilesNew = verifyMap(id)
		waitTotals.Done()
	}()
	id.parseSig(c)
	id.IO.ReportValid = false
	sigState := id.validateSig()
	waitTotals.Wait()
	id.reportDir()
	id.IO.Start = time.Now()
	if sigState {
		id.IO.ReportValid = true
		id.report()
		return id.IO.FilesFail == 0
	}
	id.report()
	if id.IO.ColorUI {
		stat, fail = _Stat, _Fail
	}
	out(stat + "SIGNATURE VALIDATION: " + fail)
	return id.IO.FilesFail == 0
}

// verigyMap ...
func verifyMap(id *HQ) (filesTotal, filesFail, filesNew uint64) {
	// global locks
	var waitDisplay, waitWorker sync.WaitGroup

	// setup channel structure
	type feed struct {
		filename string
		hash     string
		chash    string
		code     bool
	}
	type failed struct {
		filename string
		reason   int    // enum err
		exp      string // file hash expected
		calc     string // file hash calculated
		cexp     string // code hash expected
		ccalc    string // code hash calculated
	}

	// setup global communication channel
	chanFeed := make(chan feed, 10000)
	chanFail := make(chan failed, 500)
	chanFound := make(chan string, 500)
	chanCurrent := make(chan []string, 1)
	chanNewFiles := make(chan uint64, 1)
	chanTotal := make(chan uint64, 1)

	// lauch global master control process
	waitWorker.Add(id.IO.CPU)
	go func() {
		waitWorker.Wait()
		close(chanFound)
		close(chanFail)
	}()

	// start thread to manage [non-blocking] display output
	chanDisplay := make(chan string, 10)
	waitDisplay.Add(1)
	go func() {
		for t := range chanDisplay {
			out(t)
		}
		waitDisplay.Done()
	}()

	// start checksum calc worker, read from chanFeed, push to out channel
	for i := 0; i < id.IO.CPU; i++ {
		go func() {
			for t := range chanFeed {
				file, err := os.Open(t.filename)
				if err != nil {
					if t.hash == _symlinkBrokenHash {
						f, err := os.Lstat(t.filename)
						switch {
						case err != nil: // is removed
							chanFail <- failed{filename: t.filename, reason: 1}
						case uint32(f.Mode())&_modeSymlink != 0: // no change, still a broken symlink
							chanFound <- t.filename
						}
						continue
					}
					_, err = os.Stat(t.filename)
					switch err.Error() {
					case "file does not exist":
						chanFail <- failed{filename: t.filename, reason: 1}
					case "permission denied":
						chanFail <- failed{filename: t.filename, reason: 2}
					default:
						chanFail <- failed{filename: t.filename, reason: 0}

					}
					continue
				}
				chanFound <- t.filename
				reader, hash := io.Reader(file), blake3New256()
				for {
					block := make([]byte, _hashBlockSize)
					l, _ := reader.Read(block)
					if l < _hashBlockSize {
						hash.Write(block)
						break
					}
					hash.Write(block)
				}
				file.Close()
				h := hash.Sum(nil)
				fHash := string(s2hex(h[:]))
				if fHash == t.hash {
					continue
				}
				switch t.code {
				case true:
					valid, cHash := codeReviewHash(t.filename)
					if !valid {
						chanFail <- failed{
							filename: t.filename,
							reason:   6,
							exp:      t.hash,
							calc:     fHash,
							cexp:     t.chash,
							ccalc:    string(cHash),
						}
						continue
					}
					if string(cHash) != t.chash {
						chanFail <- failed{
							filename: t.filename,
							reason:   5,
							exp:      t.hash,
							calc:     fHash,
							cexp:     t.chash,
							ccalc:    string(cHash),
						}
						continue
					}
					chanFail <- failed{
						filename: t.filename,
						reason:   4,
						exp:      t.hash,
						calc:     fHash,
						cexp:     t.chash,
						ccalc:    string(cHash),
					}
					continue
				case false:
					chanFail <- failed{filename: t.filename, reason: 3, exp: t.hash, calc: fHash}
					continue
				}
			}
			waitWorker.Done()
		}()
	}

	// feeder [fast hot path, small branch tree]
	go func() {
		r := decompressReadFile(id.IO.FileName[:len(id.IO.FileName)-4])
		sizeMap := len(r)
		var total uint64
		filename, hash, chash, code := make([]byte, 0, 256), make([]byte, 0, 64), make([]byte, 0, 64), false
		for i := 0; i < sizeMap; i++ {
			if r[i] == _linefeed {
				if len(filename) == 0 {
					continue
				}
				if i+1+64 < sizeMap && r[i+1] != _linefeed { // hash found
					hash = r[i+1 : i+65]
					i += 64 + 1
					if i+1+64 < sizeMap && r[i+1] != _linefeed { // optional chash detected
						code = true
						chash = r[i+1 : i+65]
						i += 64 + 1
					}
				} else {
					chanDisplay <- "[error] input map is corrupt [last valid: " + string(filename) + "]"
					break
				}
				chanFeed <- feed{
					filename: string(filename),
					hash:     string(hash),
					chash:    string(chash),
					code:     code,
				}
				filename, hash, chash, code = nil, nil, nil, false
				total++
				continue
			}
			filename = append(filename, r[i])
		}
		close(chanFeed)
		chanTotal <- total
		close(chanTotal)
	}()

	// collect current filesystem state
	go func() {
		chanCurrent <- recursiveFileList(id.IO.DirName, 2)
		close(chanCurrent)
	}()

	// collect chanFound, diff against current state
	go func() {
		if id.IO.ColorUI {
			fnew, cOFF = _Fnew, _Off
		}
		var foundlist []string
		for found := range chanFound {
			foundlist = append(foundlist, found)
		}
		var totalNew uint64
		current := <-chanCurrent
		for _, found := range current {
			hit := false
			for _, item := range foundlist {
				if item == found {
					hit = true
					break
				}
			}
			if hit {
				continue
			}
			totalNew++
			chanDisplay <- fnew + found + cOFF
		}
		chanNewFiles <- totalNew
	}()

	// collect chanFail
	if id.IO.ColorUI {
		aON, bON, cON, gON, cOFF = _Alert, _Blue, _Cyan, _AlertG, _Off
		file, errc, exp, calc, cexp, ccalc = _File, _Errc, _Exp, _Calc, _Cexp, _Ccalc
	}
	for t := range chanFail {
		var r string
		filesFail++
		switch {
		case len(t.filename) > 120:
			r = file + bON + "\n" + t.filename + cOFF + "\n"
		default:
			r = file + bON + t.filename + cOFF + "\n"
		}
		e := r + errc + aON
		switch t.reason {
		case 0:
			chanDisplay <- e + _errFileAccess + cOFF + "\n"
		case 1:
			chanDisplay <- e + _errFileNotExist + cOFF + "\n"
		case 2:
			chanDisplay <- e + _errFilePermission + cOFF + "\n"
		case 3:
			e = e + _errFileChecksum + cOFF
			chanDisplay <- e + "\n" + exp + cON + t.exp + cOFF + "\n" + calc + cON + t.calc + cOFF + "\n"
		case 4:
			x := errc + gON + _errChashOK + cOFF + "\n"
			e = e + _errFileChecksum + cOFF
			chanDisplay <- e + "\n" + exp + cON + t.exp + cOFF + "\n" + calc + cON + t.calc + cOFF + "\n" + x + cexp + cON + t.cexp + cOFF + "\n" + ccalc + cON + t.ccalc + cOFF + "\n"
		case 5:
			x := errc + aON + _errChashFail + cOFF + "\n"
			e = e + _errFileChecksum + cOFF
			chanDisplay <- e + "\n" + exp + cON + t.exp + cOFF + "\n" + calc + cON + t.calc + cOFF + "\n" + x + cexp + cON + t.cexp + cOFF + "\n" + ccalc + cON + t.ccalc + cOFF + "\n"
		case 6:
			x := errc + aON + _errChashUnable + cOFF + "\n"
			e = e + _errFileChecksum + cOFF
			chanDisplay <- e + "\n" + exp + cON + t.exp + cOFF + "\n" + calc + cON + t.calc + cOFF + "\n" + x + cexp + cON + t.cexp + cOFF + "\n" + ccalc + cON + t.ccalc + cOFF + "\n"
		}
	}
	filesNew = <-chanNewFiles
	close(chanDisplay)
	waitDisplay.Wait()
	filesTotal = <-chanTotal
	return filesTotal, filesFail, filesNew
}
