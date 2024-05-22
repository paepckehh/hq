package hq

import (
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/exp/mmap"
	"paepcke.de/hq/blake3"
)

// setup channel struct
type obj struct {
	filename []byte
	hash     []byte
	chash    []byte
	code     bool
}

var (
	chan_out         = make(chan obj, 100)
	chan_feed        = make(chan string, 10000)
	sepone    []byte = []byte("\n")
	septwo    []byte = []byte("\n\n")
)

func DirSign(c *Config) bool {
	id := newHQMT()
	id.IO.DirName = c.FileName
	id.IO.MapClean = isMapClean()
	id.IO.TSS = strconv.FormatInt(id.IO.Start.Unix(), 10)
	id.IO.Silent = c.Silent
	id.IO.FileName = c.FileName
	switch {
	case id.IO.FileName == ".":
		id.IO.FileName = ".hqMAP." + id.IO.TSS + "." + unix2RFC3339(id.IO.TSS) + _compressed_file_ext
	default:
		id.IO.FileName = id.IO.FileName + "/" + ".hqMAP." + id.IO.TSS + "." + unix2RFC3339(id.IO.TSS) + _compressed_file_ext
	}

	// setup channel & wait groups
	wait_worker_done := sync.WaitGroup{}
	wait_worker_done.Add(id.IO.CPU)
	chan_count := make(chan uint64, 1)
	chan_end := make(chan time.Time, 1)

	// lauch global master control process
	go func() {
		wait_worker_done.Wait()
		close(chan_out)
	}()

	// collect chan_out -> data slice & write as compressed map, report, sign
	go func() {
		var (
			data  []byte
			total uint64
		)
		for t := range chan_out {
			data = append(data, []byte(t.filename)...)
			data = append(data, []byte(t.hash)...)
			if t.code {
				data = append(data, []byte(t.chash)...)
			}
			total++
		}
		compressWriteFile(id.IO.FileName, data, _compressed_map_level, 0o660)
		chan_count <- total
		close(chan_count)
		chan_end <- time.Now()
		close(chan_end)
	}()

	// start case specific hash worker group
	switch c.CodeReview {
	case true:
		for i := 0; i < id.IO.CPU; i++ {
			go func() {
				var chash *[]byte
				var code bool
				for t := range chan_feed {
					file, _ := os.Open(t)
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
					code, chash = codeReviewHash(t)
					switch code {
					case true:
						chan_out <- obj{
							filename: append([]byte(t), sepone...),
							hash:     append(s2hex(h[:]), sepone...),
							chash:    append(*chash, septwo...),
							code:     true,
						}
					case false:
						chan_out <- obj{
							filename: append([]byte(t), sepone...),
							hash:     append(s2hex(h[:]), septwo...),
							code:     false,
						}
					}
				}
				wait_worker_done.Done()
			}()
		}
	case false:
		for i := 0; i < id.IO.CPU; i++ {
			go func() {
				for t := range chan_feed {
					file, err := mmap.Open(t)
					if err != nil {
						time.Sleep(3 * time.Second)
						panic("mmap faild " + err.Error())
					}
					hash := blake3.New256()
					all := make([]byte, file.Len())
					_, err = file.ReadAt(all, 0)
					if err != nil {
						time.Sleep(3 * time.Second)
						panic("mmap: " + err.Error())
					}
					hash.Write(all)
					file.Close()
					h := hash.Sum256C()
					chan_out <- obj{
						filename: append([]byte(t), sepone...),
						hash:     append(s2hex(h[:]), septwo...),
					}
				}
				wait_worker_done.Done()
			}()
		}
	}

	// singleThread feeder
	go func() {
		path := id.IO.DirName
		list, err := os.ReadDir(path)
		if err != nil {
			errExit("unable to read directory [" + path + "] [" + err.Error() + "]")
		}
		switch path {
		case "/":
		case ".":
			path = ""
		default:
			path += "/"
		}
		for _, item := range list {
			ft := uint32(item.Type())
			name := path + item.Name()
			switch {
			case ft&_modeSymlink != 0:
				symtarget, err := os.Readlink(name)
				if err != nil {
					symtarget = "unresolvable symlink [" + err.Error() + "]"
				}
				chan_out <- obj{
					filename: append([]byte(name), sepone...),
					hash:     append([]byte(symtarget), septwo...),
				}
				continue
			case ft&_modeDir != 0:
				walk(name)
			case id.IO.MapClean && len(name) > 39 && name[:6] == ".hqMAP":
				continue
			default:
				chan_feed <- name
			}
		}
		if id.IO.MapClean {
			cleanMapFiles(id.IO.DirName)
		}
		close(chan_feed)
	}()

	// prep sign
	if !c.MapOnly {
		// now, everything is busy in the background, time to keep the user busy as well
		// ask for creds and compute hash cube in parallel (b/c hasher thread can be IO limited)
		id.IO.ReportValid = false
		id = readPublicKey(id, "me")
		id = getPASS(id, "pending hqMAP sign operation ["+id.IO.DirName+"]")
		id = unlockHQ(id)
	}

	// wait till all threads done, report, sign
	id.IO.FilesTotal = <-chan_count
	id.IO.ReportValid = false
	id.IO.End = <-chan_end
	report_dir(id)
	if c.MapOnly {
		return true
	}
	id.IO.MSG = getMSGHash(id.IO.FileName)
	id.IO.End = time.Time{}
	id.IO.Start = time.Now()
	id = genSIG(id)
	report(id)
	id = writeSIG(id)
	return true
}

func walk(path string) {
	list, err := os.ReadDir(path)
	if err != nil {
		if path != "" {
			errOut("unable to read directory [" + path + "] [" + err.Error() + "]")
		}
		return
	}
	switch path {
	case "/":
	case ".":
		path = ""
	default:
		path += "/"
	}
	for _, item := range list {
		ft := uint32(item.Type())
		name := path + item.Name()
		switch {
		case ft&_modeSymlink != 0:
			symtarget, err := os.Readlink(name)
			if err != nil {
				symtarget = "unresolvable symlink [" + err.Error() + "]"
			}
			chan_out <- obj{
				filename: append([]byte(name), sepone...),
				hash:     append([]byte(symtarget), septwo...),
			}
			continue
		case ft&_modeDir != 0:
			walk(name)
		default:
			chan_feed <- name
		}
	}
}
