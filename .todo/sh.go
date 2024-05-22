package hq

import (
	"context"
	"os"

	"paepcke.de/paepcke/hq/sh/interp"
	"paepcke.de/paepcke/hq/sh/syntax"
)

func posixRUN(c *Config) bool {
	if _sh == "builtin" {
		reader, err := os.Open(c.FileName)
		if err != nil {
			return false
		}
		r, err := interp.New(interp.StdIO(os.Stdin, os.Stdout, os.Stderr))
		if err != nil {
			return false
		}
		prog, err := syntax.NewParser().Parse(reader, c.FileName)
		if err != nil {
			return false
		}
		r.Reset()
		ctx := context.Background()
		r.Run(ctx, prog)
		return true
	}
	errout("internal posix shell script interpreter disabled via build-time option")
	return false
}
