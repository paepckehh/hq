package hq

import (
	"io"
	"io/fs"
	"math/bits"
	"os"
	"runtime"
	"sync"
	"syscall"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/term"
)

const (
	_modeDir     uint32 = 1 << (32 - 1 - 0)
	_modeSymlink uint32 = 1 << (32 - 1 - 4)
)

//
// DISPLAY IO SECTION
//

// out ...
func out(msg string) {
	os.Stdout.Write([]byte(msg + "\n"))
}

// outPlain ...
func outPlain(msg string) {
	os.Stdout.Write([]byte(msg))
}

//
// KEYBOARD IO SECTION
//

// getRune ...
func getRune() byte {
	if oldState, err := term.MakeRaw(0); err != nil {
		panic(err)
	} else {
		//nolint:all - there is no alternative/reporting if this fails
		defer term.Restore(0, oldState)
	}
	var buf [1]byte
	if n, err := syscall.Read(0, buf[:]); n == 0 || err != nil {
		panic(err)
	}
	return buf[0]
}

// readLine ...
func readLine(name string) string {
	outPlain(name)
	line, exit := []byte{}, false
	for {
		v := getRune()
		switch v {
		case 127, 8:
			if l := len(line); l > 0 {
				line = line[:l-1]
				os.Stdout.Write(append([]byte{}, v))
			}
		case 13, 10:
			exit = true
		case 0:
		default:
			line = append(line, v)
			os.Stdout.Write(append([]byte{}, v))
		}
		if exit {
			break
		}
	}
	os.Stdout.Write([]byte("\n"))
	return string(line)
}

// readPassword ...
func readPassword(name string, masked bool) string {
	outPlain(name)
	var pass, bs, mask []byte
	if masked {
		bs = []byte("\b \b")
		mask = []byte("*")
	}
	exit := false
	for {
		v := getRune()
		switch v {
		case 127, 8:
			if l := len(pass); l > 0 {
				pass = pass[:l-1]
				os.Stdout.Write(bs)
			}
		case 13, 10:
			exit = true
		case 0:
		default:
			pass = append(pass, v)
			os.Stdout.Write(mask)
		}
		if exit {
			break
		}
	}
	os.Stdout.Write([]byte("\n"))
	return string(pass)
}

//
// COMMANDLINE ARGS, PIPE AND ENV SECTION
//

// getArgs ...
func getArgs() [10]string {
	var param [10]string
	l := len(os.Args)
	if l > 2 {
		offset := 2
		action := os.Args[1]
		if action == "r" || action == "run" {
			offset++
		}
		for i := offset; i < l; i++ {
			param[i-offset] = os.Args[i]
		}
	}
	return param
}

// isEnv ...
func isEnv(in string) bool {
	if _, ok := syscall.Getenv(in); ok {
		return true
	}
	return false
}

// isPipe ...
func isPipe() bool {
	out, _ := os.Stdin.Stat()
	return out.Mode()&os.ModeCharDevice == 0
}

// getPipe ...
func getPipe() string {
	pipe, err := io.ReadAll(os.Stdin)
	if err != nil {
		errExit("while reading data from pipe")
	}
	return string(pipe)
}

//
// FILE IO SECTION
//

// isDir ...
func isDir(filename string) bool {
	fi, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return uint32(fi.Mode())&_modeDir != 0
}

// isReadable ...
func isReadable(filename string) bool {
	f, err := os.Open(filename)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// readFileErrExit ...
func readFileErrExit(filename string) (data []byte) {
	var err error
	if data, err = os.ReadFile(filename); err != nil {
		errExit("unable to read file [" + filename + "]" + "[" + err.Error() + "]")
	}
	return data
}

// writeFileErrExit writes a file and flushes via f.Sync cache to phys disk
func writeFileErrExit(filename string, data []byte, filemode fs.FileMode) {
	if err := os.WriteFile(filename, data, filemode); err != nil {
		errExit("unable to write file [" + filename + "]" + "[" + err.Error() + "]")
	}
	f, err := os.Open(filename)
	if err != nil {
		errExit("unable to [sync|verify] file on disk status [" + filename + "]" + "[" + err.Error() + "]")
	}
	defer f.Close()
	err = f.Sync()
	if err != nil {
		errExit("unable to sync file to disk [" + filename + "]" + "[" + err.Error() + "]")
	}
}

// recursiveFileList ...
func recursiveFileList(path string, worker int) []string {
	chanNames := make(chan string, 1)
	chanReport := make(chan []string, 1)
	go func() {
		var list []string
		for name := range chanNames {
			list = append(list, name)
		}
		chanReport <- list
	}()
	dirlist := readDir(path)
	for _, item := range dirlist {
		name := fixPath(path) + item.Name()
		switch {
		case uint32(item.Type())&_modeDir != 0:
			fastWalk(name, chanNames, worker)
		case len(name) > 39 && name[:6] == ".hqMAP":
			continue
		default:
			chanNames <- name
		}
	}
	close(chanNames)
	return <-chanReport
}

// walk ...
func walk(path string, chanNames chan string) {
	list, err := os.ReadDir(path)
	if err != nil {
		if path != "" {
			errOut("unable to read directory [" + path + "] [" + err.Error() + "]")
		}
		return
	}
	for _, item := range list {
		name := path + "/" + item.Name()
		switch {
		case uint32(item.Type())&_modeDir != 0:
			walk(name, chanNames)
		default:
			chanNames <- name
		}
	}
}

// fastWalk ...
func fastWalk(path string, chanNames chan string, threads int) {
	bg := sync.WaitGroup{}
	chanDir := make(chan string, 10000)
	for i := 0; i < threads; i++ {
		go func() {
			for path := range chanDir {
				list, err := os.ReadDir(path)
				if err != nil {
					errOut("unable to read directory [" + path + "] [" + err.Error() + "]")
					bg.Done()
					continue
				}
				for _, item := range list {
					name := path + "/" + item.Name()
					switch {
					case uint32(item.Type())&_modeDir != 0:
						bg.Add(1)
						chanDir <- name
					default:
						chanNames <- name
					}
				}
				bg.Done()
			}
		}()
	}
	bg.Add(1)
	chanDir <- path
	bg.Wait()
	close(chanDir)
}

// fixPath ...
func fixPath(path string) string {
	switch path {
	case "/":
		return path
	case ".":
		return ""
	default:
		return path + "/"
	}
}

// readDir ...
func readDir(path string) (list []fs.DirEntry) {
	var err error
	if list, err = os.ReadDir(path); err != nil {
		errExit("unable to list directory [" + path + "]")
	}
	return list
}

//
// FILE IO COMPRESSION SECTION
//

// compressWriteFile ...
func compressWriteFile(filename string, data []byte, level int, filemode fs.FileMode) {
	writeFileErrExit(filename, compressZstd(data, level), filemode)
}

// decompressReadFile ...
func decompressReadFile(filename string) (data []byte) {
	return decompressZstd(readFileErrExit(filename))
}

// decompressZstd ...
func decompressZstd(message []byte) []byte {
	e, _ := zstd.NewReader(nil)
	dst, _ := e.DecodeAll(message, nil)
	e.Close()
	return dst
}

// compressZstd ...
func compressZstd(message []byte, level int) []byte {
	// @UPSTREAM FIX ISSUE
	// compress/zstd encoder MaxWindowSize 32bit OS mem alloc fail hack
	threads := runtime.NumCPU()
	if bits.UintSize == 32 {
		runtime.GC()
		threads = 1
	}
	e, _ := zstd.NewWriter(nil,
		// zstd.WithWindowSize(zstd.MaxWindowSize),
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)),
		zstd.WithEncoderCRC(false),
		zstd.WithZeroFrames(false),
		zstd.WithLowerEncoderMem(false),
		zstd.WithAllLitEntropyCompression(false),
		zstd.WithNoEntropyCompression(true),
		zstd.WithEncoderConcurrency(threads))
	dst := e.EncodeAll(message, nil)
	e.Close()
	return dst
}
