// package hq
package hq

// import ...
import (
	"os"
	"os/exec"
)

// runExec ...
func (id *HQ) runExec() bool {
	s := matchShebang(id.IO.TokenExec)
	if s.interp == "disabled" {
		errExit("executable interpreter [" + s.name + "] for [" + s.ext + "] is explicitly disabled by security policy")
	}
	var (
		err error
		f   *os.File
	)
	switch {
	case id.IO.PlainTextScript:
		f, err = os.Open(id.IO.FileName)
		if err != nil {
			errExit("unable to open file [" + id.IO.FileName + "] [" + err.Error() + "]")
		}
		f.Close()
	default:
		script := string(decompressZstd(id.IO.SCRIPT))
		f, err = os.CreateTemp("/var/tmp", "scratchpad")
		if err != nil {
			errExit("unable to create shell temp scratch file")
		}
		if _, err := f.Write([]byte(script)); err != nil {
			errExit("unable to write to shell temp scratch file")
		}
		defer os.Remove(f.Name())
	}
	f.Close()
	p := getArgs()
	cmd := exec.Command(s.interp, f.Name(), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9])
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Start()
	cmd.Wait()
	return true
}

// runExecPlain ...
func (c *Config) runExecPlain() bool {
	id := &HQ{
		ID{},
		IO{
			TokenExec:       "POSIX=",
			PlainTextScript: true,
			FileName:        c.FileName,
		},
	}
	return id.runExec()
}
