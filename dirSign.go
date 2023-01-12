package hq

import (
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

// dirSign ...
func (c *Config) dirSign() bool {
	id := NewHQ(c)
	id.IO.DirName = c.FileName
	id.IO.MapClean = isMapClean()
	id.IO.TSS = strconv.FormatInt(id.IO.Start.Unix(), 10)
	id.IO.Silent = c.Silent
	id.IO.FileName = c.FileName
	switch {
	case id.IO.FileName == ".":
		id.IO.FileName = ".hqMAP." + id.IO.TSS + "." + unix2RFC3339(id.IO.TSS) + _compressedFileExt
	default:
		id.IO.FileName = id.IO.FileName + "/" + ".hqMAP." + id.IO.TSS + "." + unix2RFC3339(id.IO.TSS) + _compressedFileExt
	}

	// defaults
	var (
		sepone         = []byte("\n")
		septwo         = []byte("\n\n")
		waitWorkerDone sync.WaitGroup
	)

	// setup channel struct
	type obj struct {
		filename []byte
		hash     []byte
		chash    []byte
		code     bool
	}

	// setup channel & wait groups
	waitWorkerDone.Add(id.IO.CPU)
	chanOut := make(chan obj, 100)
	chanFeed := make(chan string, 10000)
	chanCount := make(chan uint64, 1)
	chanEnd := make(chan time.Time, 1)

	// lauch global master control process
	go func() {
		waitWorkerDone.Wait()
		close(chanOut)
	}()

	// collect chanOut -> data slice & write as compressed map, report, sign
	go func() {
		var (
			data  []byte
			total uint64
		)
		for t := range chanOut {
			data = append(data, []byte(t.filename)...)
			data = append(data, []byte(t.hash)...)
			if t.code {
				data = append(data, []byte(t.chash)...)
			}
			total++
		}
		compressWriteFile(id.IO.FileName, data, _compressedMapLevel, 0o660)
		chanCount <- total
		close(chanCount)
		chanEnd <- time.Now()
		close(chanEnd)
	}()

	// start case specific hash worker group
	switch c.CodeReview {
	case true:
		for i := 0; i < id.IO.CPU; i++ {
			go func() {
				var chash []byte
				var code bool
				for t := range chanFeed {
					file, _ := os.Open(t)
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
					code, chash = codeReviewHash(t)
					switch code {
					case true:
						if chash == nil {
							continue
						}
						chanOut <- obj{
							filename: append([]byte(t), sepone...),
							hash:     append(s2hex(h[:]), sepone...),
							chash:    append(chash, septwo...),
							code:     true,
						}
					case false:
						chanOut <- obj{
							filename: append([]byte(t), sepone...),
							hash:     append(s2hex(h[:]), septwo...),
							code:     false,
						}
					}
				}
				waitWorkerDone.Done()
			}()
		}
	case false:
		for i := 0; i < id.IO.CPU; i++ {
			go func() {
				for t := range chanFeed {
					file, _ := os.Open(t)
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
					chanOut <- obj{
						filename: append([]byte(t), sepone...),
						hash:     append(s2hex(h[:]), septwo...),
					}
				}
				waitWorkerDone.Done()
			}()
		}
	}

	// feeder [fastwalk]
	go func() {
		path := id.IO.DirName
		dirlist, err := os.ReadDir(path)
		if err != nil {
			errExit("unable to read directory [" + path + "] [" + err.Error() + "]")
		}
		for _, item := range dirlist {
			name := fixPath(path) + item.Name()
			inodeType := uint32(item.Type())
			switch {
			case inodeType&_modeSymlink != 0:
				chanFeed <- name // profile symbolic links - but do not [recursive] follow
			case inodeType&_modeDir != 0:
				walk(name, chanFeed)
			case id.IO.MapClean && len(name) > 39 && name[:6] == ".hqMAP":
				continue
			default:
				chanFeed <- name
			}
		}
		if id.IO.MapClean {
			cleanMapFiles(id.IO.DirName)
		}
		close(chanFeed)
	}()

	// prep sign
	if !c.MapOnly {
		// now, everything is busy in the background, time to keep the user busy as well
		// ask for creds and compute hash cube in parallel (b/c hasher thread can be IO limited)
		id.IO.ReportValid = false
		id.readPublicKey("me")
		id.passEntry("pending hqMAP sign operation [" + id.IO.DirName + "]")
		id.unlockHQ()
	}

	// wait till all threads done, report, sign
	id.IO.FilesTotal = <-chanCount
	id.IO.ReportValid = false
	id.IO.End = <-chanEnd
	id.reportDir()
	if c.MapOnly {
		return true
	}
	id.IO.MSG = getMSGHash(id.IO.FileName)
	id.IO.End = time.Time{}
	id.IO.Start = time.Now()
	id.genSig()
	id.report()
	id.writeSig()
	return true
}
