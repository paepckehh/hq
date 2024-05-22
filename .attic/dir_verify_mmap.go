package hq

import (
	"os"
	"sync"
	"time"

	"golang.org/x/exp/mmap"
	"paepcke.de/hq/blake3"
)

func DirVerify(c *Config) bool {
	id := newHQMT()
	id.IO.DirName = c.FileName
	id.IO.ReportValid = true
	id.IO.FileName = getMAP(c)
	id.IO.FileName += _ext_signature
	id.IO.Silent = c.Silent
	chan_total := make(chan uint64, 1)
	chan_total_new := make(chan uint64, 1)
	chan_total_fail := make(chan uint64, 1)
	go func() {
		total, total_fail, total_new := verifyMAP(id)
		chan_total <- total
		chan_total_new <- total_new
		chan_total_fail <- total_fail
		close(chan_total)
		close(chan_total_new)
		close(chan_total_fail)
	}()
	id = parseSIG(id, c)
	id.IO.ReportValid = false
	signature_status := validateSIG(id)
	id.IO.FilesTotal = <-chan_total
	id.IO.FilesNew = <-chan_total_new
	id.IO.FilesFail = <-chan_total_fail
	report_dir(id)
	id.IO.Start = time.Now()
	if signature_status {
		id.IO.ReportValid = true
		report(id)
		return id.IO.FilesFail == 0
	}
	report(id)
	if id.IO.ColorUI {
		stat, fail = __stat, __fail
	}
	out(stat + "SIGNATURE VALIDATION: " + fail)
	return id.IO.FilesFail == 0
}

func verifyMAP(id *HQ) (uint64, uint64, uint64) {
	// global locks
	var wait_display_done, wait_worker_done sync.WaitGroup

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
	chan_feed := make(chan feed, 10000)
	chan_fail := make(chan failed, 500)
	chan_found := make(chan string, 500)
	chan_curr := make(chan []string, 1)
	chan_new := make(chan uint64, 1)
	chan_total := make(chan uint64, 1)

	// lauch global master control process
	wait_worker_done.Add(id.IO.CPU)
	go func() {
		wait_worker_done.Wait()
		close(chan_found)
		close(chan_fail)
	}()

	// start thread to manage [non-blocking] display output
	chan_display := make(chan string, 10)
	wait_display_done.Add(1)
	go func() {
		for t := range chan_display {
			out(t)
		}
		wait_display_done.Done()
	}()

	// start checksum calc worker, read from chan_feed, push to out channel
	for i := 0; i < id.IO.CPU; i++ {
		go func() {
			for t := range chan_feed {
				f, err := os.Stat(t.filename)
				if err != nil {
					switch err.Error() {
					case "file does not exist":
						chan_fail <- failed{filename: t.filename, reason: 1}
					case "permission denied":
						chan_fail <- failed{filename: t.filename, reason: 2}
					default:
						f, err := os.Lstat(t.filename)
						switch {
						case err != nil: // is removed
							chan_fail <- failed{filename: t.filename, reason: 1}
							continue
						case uint32(f.Mode())&_modeSymlink != 0: // is invalid symlink
							chan_found <- t.filename
							continue
						}
						chan_fail <- failed{filename: t.filename, reason: 0}
					}
					continue
				}
				fm := uint32(f.Mode())
				if fm&_modeDir != 0 {
					chan_found <- t.filename // unchanged symlink dir
					continue
				}
				file, err := mmap.Open(t.filename)
				if err != nil {
					panic("mmap faild " + err.Error())
				}
				chan_found <- t.filename
				hash := blake3.New256()
				all := make([]byte, file.Len())
				_, err = file.ReadAt(all, 0)
				if err != nil {
					panic("mmap: " + err.Error())
				}
				hash.Write(all)
				file.Close()
				h := hash.Sum256C()
				fHash := string(s2hex(h[:]))
				if fHash == t.hash {
					continue
				}
				switch t.code {
				case true:
					valid, cHash := codeReviewHash(t.filename)
					if !valid {
						chan_fail <- failed{
							filename: t.filename,
							reason:   6,
							exp:      t.hash,
							calc:     fHash,
							cexp:     t.chash,
							ccalc:    string(*cHash),
						}
						continue
					}
					if string(*cHash) != t.chash {
						chan_fail <- failed{
							filename: t.filename,
							reason:   5,
							exp:      t.hash,
							calc:     fHash,
							cexp:     t.chash,
							ccalc:    string(*cHash),
						}
						continue
					}
					chan_fail <- failed{
						filename: t.filename,
						reason:   4,
						exp:      t.hash,
						calc:     fHash,
						cexp:     t.chash,
						ccalc:    string(*cHash),
					}
					continue
				case false:
					chan_fail <- failed{filename: t.filename, reason: 3, exp: t.hash, calc: fHash}
					continue
				}
			}
			wait_worker_done.Done()
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
					chan_display <- "[error] input map is corrupt [last valid: " + string(filename) + "]"
					break
				}
				chan_feed <- feed{
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
		close(chan_feed)
		chan_total <- total
		close(chan_total)
	}()

	// collect current filesystem state
	go func() {
		l := recursiveFileList(id.IO.DirName, 2)
		chan_curr <- l
		close(chan_curr)
	}()

	// collect chan_found, diff against current state
	go func() {
		if id.IO.ColorUI {
			fnew, c_off = __fnew, __OFF
		}
		var foundlist []string
		for found := range chan_found {
			foundlist = append(foundlist, found)
		}
		var total_new uint64
		current := <-chan_curr
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
			total_new++
			chan_display <- fnew + found + c_off
		}
		chan_new <- total_new
	}()

	// collect chan_fail
	var total_fail uint64
	if id.IO.ColorUI {
		a_on, b_on, c_on, g_on, c_off = __ALERT, __BLUE, __CYAN, __ALERT_G, __OFF
		file, errc, exp, calc, cexp, ccalc = __file, __errc, __exp, __calc, __cexp, __ccalc
	}
	for t := range chan_fail {
		var r string
		total_fail++
		switch {
		case len(t.filename) > 120:
			r = file + b_on + "\n" + t.filename + c_off + "\n"
		default:
			r = file + b_on + t.filename + c_off + "\n"
		}
		e := r + errc + a_on
		switch t.reason {
		case 0:
			chan_display <- e + _err_file_access + c_off + "\n"
		case 1:
			chan_display <- e + _err_file_not_exist + c_off + "\n"
		case 2:
			chan_display <- e + _err_file_permission + c_off + "\n"
		case 3:
			e = e + _err_file_checksum + c_off
			chan_display <- e + "\n" + exp + c_on + t.exp + c_off + "\n" + calc + c_on + t.calc + c_off + "\n"
		case 4:
			x := errc + g_on + _err_chash_ok + c_off + "\n"
			e = e + _err_file_checksum + c_off
			chan_display <- e + "\n" + exp + c_on + t.exp + c_off + "\n" + calc + c_on + t.calc + c_off + "\n" + x + cexp + c_on + t.cexp + c_off + "\n" + ccalc + c_on + t.ccalc + c_off + "\n"
		case 5:
			x := errc + a_on + _err_chash_fail + c_off + "\n"
			e = e + _err_file_checksum + c_off
			chan_display <- e + "\n" + exp + c_on + t.exp + c_off + "\n" + calc + c_on + t.calc + c_off + "\n" + x + cexp + c_on + t.cexp + c_off + "\n" + ccalc + c_on + t.ccalc + c_off + "\n"
		case 6:
			x := errc + a_on + _err_chash_unable + c_off + "\n"
			e = e + _err_file_checksum + c_off
			chan_display <- e + "\n" + exp + c_on + t.exp + c_off + "\n" + calc + c_on + t.calc + c_off + "\n" + x + cexp + c_on + t.cexp + c_off + "\n" + ccalc + c_on + t.ccalc + c_off + "\n"
		}
	}
	new_files := <-chan_new
	close(chan_display)
	wait_display_done.Wait()
	return <-chan_total, total_fail, new_files
}
