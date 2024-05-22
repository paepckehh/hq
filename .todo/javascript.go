package hq

import (
	"context"
	"os"

	"paepcke.de/paepcke/hq/javascript/interp"
	"paepcke.de/paepcke/hq/javascript/parser"
)

func javascriptRUN(c *Config) bool {
	if _javascript == "builtin" {
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
	errout("internal javascript script interpreter disabled via build-time option")
	return false
}
