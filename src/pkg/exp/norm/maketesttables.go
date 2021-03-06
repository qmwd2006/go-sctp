// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build ignore

// Generate test data for trie code.

package main

import (
	"fmt"
)

func main() {
	printTestTables()
}

// We take the smallest, largest and an arbitrary value for each 
// of the UTF-8 sequence lengths.
var testRunes = []rune{
	0x01, 0x0C, 0x7F, // 1-byte sequences
	0x80, 0x100, 0x7FF, // 2-byte sequences
	0x800, 0x999, 0xFFFF, // 3-byte sequences
	0x10000, 0x10101, 0x10FFFF, // 4-byte sequences
	0x200, 0x201, 0x202, 0x210, 0x215, // five entries in one sparse block
}

const fileHeader = `// Generated by running
//	maketesttables
// DO NOT EDIT

package norm

`

func printTestTables() {
	fmt.Print(fileHeader)
	fmt.Printf("var testRunes = %#v\n\n", testRunes)
	t := newNode()
	for i, r := range testRunes {
		t.insert(r, uint16(i))
	}
	t.printTables("testdata")
}
