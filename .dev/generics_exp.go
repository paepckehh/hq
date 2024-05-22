package hq

// mem alloc optimized multi slice append
func multiSliceAppend(in ...[]byte) []byte {
	size := 0
	for _, t := range in {
		size += len(t)
	}

	// make target slice
	out := make([]byte, 0, size)

	// assemble
	for _, t := range in {
		out = append(out, t...)
	}
	return out
}

func multiSliceAppendSEP(in ...[]byte) []byte {
	size := 0
	for _, t := range in {
		size += len(t)
		size++
	}
	out := make([]byte, 0, size)
	for _, t := range in {
		out = append(out, t...)
		out = append(out, '#')
	}
	return out
}
