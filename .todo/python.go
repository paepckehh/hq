package hq

import (
	"context"
	"os"

	"paepcke.de/paepcke/hq/python/interp"
	"paepcke.de/paepcke/hq/python/parser"
)

func pythonRUN(c *Config) bool {
	if _awk == "builtin" {
		reader, err := os.Open(c.FileName)
		if err != nil {
			return false
		}
		// XXX TODO
		// r, err := interp.New(interp.StdIO(os.Stdin, os.Stdout, os.Stderr))
		// if err != nil {
		//	return false
		// }
		// prog, err := parser.NewParser().Parse(reader, c.FileName)
		// if err != nil {
		//	return false
		// }
		// r.Reset()
		// ctx := context.Background()
		// r.Run(ctx, prog)
		// return true
	}
	errout("internal python script interpreter disabled via build-time option")
	return false
}
