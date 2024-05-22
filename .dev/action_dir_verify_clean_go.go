package hq

import (
	"io"
	"os"
	"sync"
	"time"

	"paepcke.de/hq/blake3"
)

func DirVerify(c *Config) bool {
	id := newHQMT()
	id.IO.DirName = c.FileName
	id.IO.ReportValid = true
	id.IO.FileName = getMAP(c)
	id.IO.FileName = id.IO.FileName + _ext_signature
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
		checksum string
	}
	type failed struct {
		filename string
		reason   int    // enum err
		exp      string // expected
		calc     string // calculated
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
				file, err := os.Open(t.filename)
				if err != nil {
					if t.checksum == _symlink_broken_hash {
						f, err := os.Lstat(t.filename)
						switch {
						case err != nil: // is removed
							chan_fail <- failed{filename: t.filename, reason: 1}
						case uint32(f.Mode())&_modeSymlink != 0: // no change, still a broken symlink
							chan_found <- t.filename
						}
						continue
					}
					_, err = os.Stat(t.filename)
					switch err.Error() {
					case "file does not exist":
						chan_fail <- failed{filename: t.filename, reason: 1}
					case "permission denied":
						chan_fail <- failed{filename: t.filename, reason: 2}
					default:
						chan_fail <- failed{filename: t.filename, reason: 0}

					}
					continue
				}
				chan_found <- t.filename
				reader, hash := io.Reader(file), blake3.New256()
				for {
					block := make([]byte, _hash_block_size)
					l, _ := reader.Read(block)
					if l < _hash_block_size {
						hash.Write(block)
						break
					}
					hash.Write(block)
				}
				file.Close()
				h := hash.Sum256C()
				if hashSum := string(s2hex(h[:])); hashSum != t.checksum {
					chan_fail <- failed{filename: t.filename, reason: 3, exp: t.checksum, calc: hashSum}
					continue
				}
			}
			wait_worker_done.Done()
		}()
	}

	// feeder [fast hot path, small branch tree]
	go func() {
		r := decompressReadFile(id.IO.FileName[:len(id.IO.FileName)-4])
		size := len(r)
		var total uint64
		var filename, hash []byte
		for i := 0; i < size; i++ {
			if r[i] == _linefeed {
				if len(filename) == 0 {
					continue
				}
				for {
					i++
					if i > size {
						chan_display <- "[error] input map is [corrupt|truncated]"
						break
					}
					if r[i] == _linefeed {
						break
					}
					hash = append(hash, r[i])
				}
				chan_feed <- feed{filename: string(filename), checksum: string(hash)}
				filename, hash = nil, nil
				total++
				continue
			}
			filename = append(filename, r[i])
		}
		close(chan_feed)
		chan_total <- total
		close(chan_total)
	}()

	/* feeder [clean-go, as reference]
	go func() {
		reader := bufio.NewScanner(bytes.NewReader(decompressReadFile(id.IO.FileName[:len(id.IO.FileName)-4])))
		var total uint64
		for reader.Scan() {
			if reader.Text() == "" {
				continue
			}
			filename := reader.Text()
			reader.Scan()
			chan_feed <- feed{filename: filename, checksum: reader.Text()}
			total++
		}
		close(chan_feed)
		chan_total <- total
		close(chan_total)
	}() */

	// collect current filesystem state
	go func() {
		fork := 0
		if id.IO.CPU > 32 { // TODO [VERIFY|ADJUST|REMOVE]
			fork = id.IO.CPU / 16 // single threaded walker could bottleneck here
		}
		l := recursiveFileList(id.IO.DirName, fork)
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
		a_on, b_on, c_on, c_off, file, errc, exp, calc = __ALERT, __BLUE, __CYAN, __OFF, __file, __errc, __exp, __calc
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
		}
	}
	new_files := <-chan_new
	close(chan_display)
	wait_display_done.Wait()
	return <-chan_total, total_fail, new_files
}
