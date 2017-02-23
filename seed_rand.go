package main

import (
	crand "crypto/rand"
	"encoding/binary"
	mrand "math/rand"
)

func init() {
	var seed [8]byte
	if _, err := crand.Read(seed[:]); err != nil {
		panic(err)
	}

	mrand.Seed(int64(binary.LittleEndian.Uint64(seed[:])))
}
