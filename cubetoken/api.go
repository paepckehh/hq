// Package cubetoken provides and [complex] [multi-] input to hash KDF [key derivation function]
package cubetoken

// import
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
