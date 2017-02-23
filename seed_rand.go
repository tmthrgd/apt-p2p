// Copyright 2015 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

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
