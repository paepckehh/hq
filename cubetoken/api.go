// Package cubetoken provides a complex KDF function
package cubetoken

import (
	"paepcke.de/signify"
	"paepcke.de/sphincs"
)

// Config ...
type Config struct {
	Progress                  bool
	ForceNoColor              bool
	Memlimit, Parallel, Layer int
	One, Two, Owner, KeyMac   [64]byte
}

// SeedToken
type SeedToken struct {
	SphincsSeed [sphincs.SeedTokenSize]byte
	SignifySeed [signify.SeedTokenSize]byte
}

// Generate ...
func Generate(c *Config) SeedToken {
	return generate(c)
}
