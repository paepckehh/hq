package hq

import (
	"strconv"
	"strings"
	"time"
)

const _hex = "0123456789abcdef"

func setByte64(in []byte) [64]byte {
	if len(in) != 64 {
		panic("unrecoveralbe internal error, unable set byte slice [lengh:" + strconv.Itoa(len(in)) + "] to []64byte")
	}
	fixed := [64]byte{}
	for i := range in {
		fixed[i] = in[i]
	}
	return fixed
}

func multiSliceAppend(in ...[]byte) (out []byte) {
	for _, t := range in {
		out = append(out, t...)
	}
	return out
}

func multiSliceAppendSEP(in ...[]byte) (out []byte) {
	for _, t := range in {
		out = append(out, t...)
		out = append(out, '#')
	}
	return out
}

func pad(in string) (out [64]byte) {
	l := len(in)
	for i := range out {
		if i < l {
			out[i] = in[i]
			continue
		}
		out[i] = '='
	}
	return out
}

func unpad(in [64]byte) (out string) {
	for i := range in {
		if in[i] == '=' {
			break
		}
		out += string(in[i])
	}
	return out
}

func padstring(in string) string {
	for len(in) < 75 {
		in += " "
	}
	return in
}

func s2hex(s []byte) []byte {
	t := make([]byte, len(s)*2)
	for i, v := range s {
		t[i*2] = _hex[v>>4]
		t[i*2+1] = _hex[v&0x0f]
	}
	return t
}

func unix2RFC3339(in string) string {
	ts, err := strconv.ParseInt(in, 10, 0)
	if err != nil {
		errExit("TSS time stamp corrupted - parse error")
	}
	return strings.ReplaceAll(time.Unix(ts, 0).Format(time.RFC3339), ":", ".")
}

func unix2RFC850(in string) string {
	ts, err := strconv.ParseInt(in, 10, 0)
	if err != nil {
		errExit("TSS time stamp corrupted - parse error")
	}
	return time.Unix(ts, 0).Format(time.RFC850)
}

type shebang struct {
	token, interp, ext, name string
}

func matchShebang(in string) shebang {
	switch in {
	case "POSIX=", "#!/bin/sh", "#!sh", "#!/usr/bin/env sh", "sh", ".sh":
		return shebang{"POSIX=", _sh, ".sh", "posix shell script"}
	case "ZSH===", "#!/usr/bin/zsh", "#!zsh", "#!/usr/bin/env zsh", "zsh", ".zsh":
		return shebang{"ZSH===", _zsh, ".zsh", "zsh shell script"}
	case "FISH==", "#!/usr/bin/fish", "#!fish", "#!/usr/bin/env fish", "fish", ".fish":
		return shebang{"FISH==", _fish, ".fish", "fish shell script"}
	case "BASH==", "#!/usr/bin/bash", "#!bash", "#!/usr/bin/env bash", "bash", ".bash":
		return shebang{"BASH==", _bash, ".bash", "bash shell script"}
	case "LUA===", "#!/usr/bin/lua", "#!lua", "#!/usr/bin/env lua", "lua", ".lua":
		return shebang{"LUA===", _lua, ".lua", "lua lang"}
	case "HACK==", "#!/usr/bin/hhvm", "#!hhvm", "#!/usr/bin/env hhvm", "hack", ".hack":
		return shebang{"LUA===", _hhvm, ".hhvm", "hack lang"}
	case "PERL==", "#!/usr/bin/perl", "#!perl", "#!/usr/bin/env perl", "perl", ".perl":
		return shebang{"PERL==", _perl, ".perl", "perl lang"}
	case "PYTHON", "#!/usr/bin/python", "#!python", "#!/usr/bin/env python", "python", ".py":
		return shebang{"PYTHON", _python, ".py", "python lang"}
	case "JS====", "#!/usr/bin/js", "#!js", "#!/usr/bin/env js", "js", ".js":
		return shebang{"JS====", _js, ".js", "javascript"}
	case "JAVA==", "#!/usr/bin/java", "#!java", "#!/usr/bin/env java", "java", ".java":
		return shebang{"JAVA==", _java, ".java", "java"}
	case "PWSH==", "#!pwsh", "#!powershell", "#!/usr/bin/env pwsh", "pwsh", ".ps":
		return shebang{"PWSH==", _pwsh, ".ps", "powershell"}
	}
	return shebang{_empty, _empty, _empty, _empty}
}

func matchFileExt(in string) (string, int) {
	l := len(in)
	switch {
	case l > 3:
		switch in[l-3:] {
		case ".sh":
			return "POSIX=", 3
		case ".py":
			return "PYTHON", 3
		case ".js":
			return "JS====", 3
		case ".ps", ".ps1":
			return "PWSH==", 3
		}
	case l > 4:
		switch in[l-4:] {
		case ".lua":
			return "LUA===", 4
		case ".zsh":
			return "ZSH===", 4
		}
	case l > 5:
		switch in[l-5:] {
		case ".fish":
			return "FISH==", 5
		case ".perl":
			return "PERL==", 5
		case ".bash":
			return "BASH==", 5
		case ".hack":
			return "HACK==", 5
		case ".java":
			return "JAVA==", 5
		}
	}
	return "", 0
}
