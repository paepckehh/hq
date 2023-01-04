// package main
package main

import (
	"os"

	"paepcke.de/hq"
)

// main ..
func main() {
	c := hq.NewConfig()
	c.ParseCmd()
	if !c.RunAction() {
		os.Exit(1)
	}
}
