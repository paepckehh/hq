package cubetoken

// generate ...
func generate(c *Config) SeedToken {
	// spinup display engine
	display.Add(1)
	go startDisplayEngine(c)

	// define layer internal function array structure
	var (
		keyfunc    [9]func(key1, key2, kmac []byte, pulse1, pulse2, pulse3, expander int) []byte
		h          [len(keyfunc)][]byte // layer internal hash slices
		k          [4][]byte            // layer keys
		kmac       = c.KeyMac[:]
		key1, key2 = append(c.One[:], c.Owner[:]...), append(c.Two[:], c.Owner[:]...)
		key3, key4 = append(c.Owner[:], c.One[:]...), append(c.Owner[:], c.Two[:]...)
	)

	// key version layer template function array
	keyfunc[0] = func(key1, key2, kmac []byte, pulse1, pulse2, pulse3, expander int) []byte {
		displayChan <- []byte("####################*")
		return argon2d(sha3E(key1, kmac, 512), blake3E(key2, kmac, 512), c.Memlimit, c.Parallel)
	}
	keyfunc[1] = func(key1, key2, kmac []byte, pulse1, pulse2, pulse3, expander int) []byte {
		displayChan <- []byte("#########*")
		return pbkdf2Sha2(blake2bE(key1, kmac, 512), sha2E(key2, kmac, 512), pulse2)
	}
	keyfunc[2] = func(key1, key2, kmac []byte, pulse1, pulse2, pulse3, expander int) []byte {
		displayChan <- []byte("############*")
		return scryptSha3(sha3E(key1, kmac, 512), shake256E(key2, kmac, 512), pulse1/2)
	}
	keyfunc[3] = func(key1, key2, kmac []byte, pulse1, pulse2, pulse3, expander int) []byte {
		displayChan <- []byte("#######*")
		return pbkdf2Blake2b(sha2E(key1, kmac, 512), blake3E(key2, kmac, 512), pulse2)
	}
	keyfunc[4] = func(key1, key2, kmac []byte, pulse1, pulse2, pulse3, expander int) []byte {
		displayChan <- []byte("##############*")
		return scryptBlake2b(shake256E(key1, kmac, pulse3), sha2E(key2, kmac, 512), pulse1)
	}
	keyfunc[5] = func(key1, key2, kmac []byte, pulse1, pulse2, pulse3, expander int) []byte {
		displayChan <- []byte("##########*")
		return pbkdf2Sha3(blake2bE(key1, kmac, 512), blake3E(key2, kmac, 512), (pulse2 / 3))
	}
	keyfunc[6] = func(key1, key2, kmac []byte, pulse1, pulse2, pulse3, expander int) []byte {
		displayChan <- []byte("#############*")
		return scryptSha2(blake3E(key1, kmac, 512), sha2E(key2, kmac, 512), pulse1+1)
	}
	keyfunc[7] = func(key1, key2, kmac []byte, pulse1, pulse2, pulse3, expander int) []byte {
		displayChan <- []byte("#########*")
		return pbkdf2Blake3(blake2bE(key1, kmac, 512), shake256E(key2, kmac, 512), (pulse2 / 3))
	}
	keyfunc[8] = func(key1, key2, kmac []byte, pulse1, pulse2, pulse3, expander int) []byte {
		displayChan <- []byte("#######*")
		return scryptBlake3(shake256E(key1, kmac, pulse3), sha3E(key2, kmac, 512), pulse1)
	}

	// main loop
	expander := c.Memlimit / 2
	pulse1, pulse2, pulse3 := 8, 512, 0
	for layer := 0; layer < c.Layer; layer++ {

		// prepare layer internal puls parameter setup for this layer pass
		expander = expander + (expander / 2) + pulse2
		if expander > c.Memlimit {
			expander = c.Memlimit/2 + 4096 + pulse2
		}
		switch {
		case pulse1 == 16:
			pulse1, pulse3 = 9, 65536
		default:
			pulse1, pulse3 = 16, 512
		}
		pulse2 = pulse1 * 48
		displayChan <- []byte("# Layer ")

		// loop through all layer functions
		for i := range keyfunc {

			// run key derivation function via keyblock func definition array
			h[i] = keyfunc[i](key1, key2, kmac, pulse1, pulse2, pulse3, expander)

			// generate input keys for next key derivation node within same layer
			key1 = append(key1, h[i][:256]...)
			key2 = append(key2, h[i][256:]...)

			// feed additional inter-layer connection data into the next node input keys
			if i < cap(keyfunc)-1 && h[i+1] != nil {
				key1 = append(key1, h[i+1][256:]...)
				key2 = append(key2, h[i+1][:256]...)
			}
		}

		// prep layer
		if layer+1 < c.Layer {

			// layer finished, assemble key-out data to add asymetric layer internal interconnects
			k[0] = multiSliceAppend(h[2], h[4], h[5], h[0], h[3], h[7])
			k[1] = multiSliceAppend(h[8], h[1], h[5], h[6], h[5])
			k[2] = multiSliceAppend(h[1], h[4], h[7])
			k[3] = multiSliceAppend(h[0], h[5], h[3], h[5], h[8])

			// assemble key layer break survial init keys for next layer
			key1 = append(k[0], k[3]...)
			key2 = append(k[1], k[2]...)
			key3 = append(k[3], k[0]...)
			key4 = append(k[2], k[1]...)
			key1 = sha3E(sha2(sha3(blake2b(shake256E(key1, kmac, 65536)))), kmac, 512)
			key2 = sha3E(sha3(sha2(blake3(shake256E(key2, kmac, 65536)))), kmac, 512)
			key3 = sha3E(sha2(sha3(blake3(shake256E(key3, kmac, 65536)))), kmac, 512)
			key4 = sha3E(sha3(sha3(blake3(shake256E(key4, kmac, 65536)))), kmac, 512)
		}
		displayChan <- []byte("##*#!\n")
	}

	// wait till display finished
	close(displayChan)
	display.Wait()

	// provide seeds
	return SeedToken{
		SphincsSeed: sphincsSeed(key1, key2),
		SignifySeed: signifySeed(key3, key4),
	}
}

// multiSliceAppend ...
func multiSliceAppend(in ...[]byte) (out []byte) {
	for _, t := range in {
		out = append(out, t...)
	}
	return out
}
