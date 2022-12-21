package hq

import (
	"os"
	"strconv"
	"syscall"
)

// action ...
func (c *Config) runAction() bool {
	ok := true
	switch c.Action {
	case "sign":
		switch c.Target {
		case "dir":
			ok = c.DirSign()
		case "file":
			ok = c.FileSign()
		case "exec":
			ok = c.FileSignExecuteable()
		default:
			panic(_errIntParser)
		}
	case "verify":
		switch c.Target {
		case "dir":
			ok = c.DirVerify()
		case "file":
			ok = c.FileVerify()
		case "exec":
			ok = c.FileVerifyExecuteable()
		default:
			panic(_errIntParser)
		}
	case "run":
		if c.PlainTextScript {
			ok = c.RunExecPlain()
		} else {
			ok = c.FileVerifyExecuteable()
		}
	case "generate":
		ok = c.Generate()
	case "pwd":
		ok = c.LegacyPass()
	case "unlock":
		ok = c.Unlock()
	case "lock":
		ok = c.Lock()
	case "bench":
		ok = c.Bench()
	case "test":
		ok = c.CryptoVerify()
	case "help":
		help()
	case "version":
		version()
	default:
		panic(_errIntParser)
	}
	return ok
}

// parseCmd ...
func (c *Config) parseCmd() {
	c.FileName = "."
	c.Target = "dir"
	cmdargs := len(os.Args)
	switch {
	case cmdargs > 1:
		x := os.Args[1]
		switch x {
		case "run", "r":
			c.Action = "run"
			c.IsExec = true
			c.RunExec = true
			if c.IsPipe {
				c.FileName = _pipe
				return
			}
		case "sign", "s":
			c.Action = "sign"
		case "code", "c":
			c.Action = "sign"
			c.CodeReview = true
		case "verify", "v":
			c.Action = "verify"
			if c.IsPipe {
				c.Target = "exec"
				c.FileName = _pipe
				return
			}
		case "generate", "gen", "g":
			c.Action = "generate"
			return
		case "pwd", "p":
			c.Action = "pwd"
			return
		case "xpwd", "x":
			c.Action = "pwd"
			c.PwdComplex = false
			return
		case "unlock", "u":
			c.Action = "unlock"
			return
		case "lock", "l":
			c.Action = "lock"
			return
		case "bench", "b":
			c.Action = "bench"
			return
		case "test", "t":
			c.Action = "test"
			return
		case "version", "-V", "--version", "-v":
			c.Action = "version"
			return
		case "help", "h", "usage", "syntax", "man", "examples", "-h", "--help":
			c.Action = "help"
			return
		case ".":
			c.Action = "verify"
			c.Silent = true
			if c.getMap() == "" {
				c.Action = "sign"
			}
			c.FileName = "."
			c.Silent = false
			return
		default:
			c.FileName = x
			if isDir(c.FileName) {
				c.Action = "verify"
				c.Silent = true
				if c.getMap() == "" {
					c.Action = "sign"
				}
				c.Silent = false
				return
			}
			c.Target = "file"
			l := len(c.FileName)
			if l > 3 {
				switch c.FileName[l-3:] {
				case ".sh":
					c.Action = "run"
					c.PlainTextScript = true
					return
				default:
				}
			}
			if l > 4 {
				switch c.FileName[l-4:] {
				case ".hqx":
					c.Action = "run"
					c.IsExec = true
					c.RunExec = true
					return
				case ".hqs":
					c.Action = "verify"
					return
				}
			}

			f, err := os.Open(c.FileName)
			if err != nil {
				errExit("unable to read file [" + c.FileName + "] [" + err.Error() + "]")
			}
			h := make([]byte, 24)
			_, _ = f.Read(h)
			f.Close()
			head := string(h)
			switch head[:9] {
			case "#!/bin/sh":
				c.Action = "run"
				c.PlainTextScript = true
				return
			default:
			}
			if head[:13] == "#!/usr/bin/hqx" {
				switch head[14:20] {
				case "##HQX#":
					c.Action = "run"
					c.IsExec = true
					c.RunExec = true
					return
				case "##HQS#":
					c.Action = "verify"
					return
				}
			}
			c.Action = "sign"
			return
		}
	default:
		if c.IsPipe {
			c.Action = "run"
			c.IsExec = true
			c.RunExec = true
			c.FileName = _pipe
			return
		}
		errsyntax("")
	}
	switch {
	case cmdargs > 2:
		c.FileName = os.Args[2]
		if isDir(c.FileName) {
			if len(os.Args) > 3 {
				l := len(os.Args[3])
				if l < 3 || l > 10 {
					errExit("please sepcify at least 3, max 10 digits")
				}
				if _, err := strconv.Atoi(os.Args[3]); err != nil {
					errExit("please sepcify digits only [min 3, max 10] , example 1634981329")
				}
				c.TargetTS = os.Args[3]
			}
			return
		}
		c.Target = "file"
		l := len(c.FileName)
		switch c.Action[0] {
		case 's':
			file, err := os.Open(c.FileName)
			if err != nil {
				errExit("unable to read file [" + c.FileName + "]")
			}
			if _, ok := syscall.Getenv(_envHQSigOnly); !ok {
				c.TokenExec, c.ScriptExtL = matchFileExt(c.FileName)
				if c.TokenExec != "" {
					c.Target = "exec"
					c.IsExec = true
					return
				}
			}
			headslice := make([]byte, 24)
			_, _ = file.Read(headslice)
			head := string(headslice)
			switch head[:9] {
			case "#!/bin/sh":
				c.TokenExec = "POSIX="
				c.Target = "exec"
				c.IsExec = true
				return
			default:
			}
		case 'v':
			if l > 4 {
				switch c.FileName[l-4:] {
				case ".hqs":
					return
				case ".hqx":
					c.Target = "exec"
					c.IsExec = true
					return
				}
			}
			c.FileName += _extSignature
			if !isReadable(c.FileName) {
				errExit("unable to access [" + c.FileName + "]")
			}
			return
		case 'r':
			if l > 3 {
				switch c.FileName[l-3:] {
				case ".sh":
					c.PlainTextScript = true
					return
				default:
				}
			}
			if l > 4 {
				switch c.FileName[l-4:] {
				case ".hqx":
					c.Target = "exec"
					c.IsExec = true
					c.RunExec = true
					return
				default:
					errExit("to run a executeable, please provide an .hqx file")
				}
			}
			errExit("... to run a hqx executeable, please provide an .hqx file")
		}
	default:
	}
}
