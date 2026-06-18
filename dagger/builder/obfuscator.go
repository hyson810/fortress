package main

import (
	"crypto/rand"
	"fmt"
)

type Obfuscator struct {
	seed       []byte
	mutations  int
	stringXor  bool
	deadCode   bool
}

func NewObfuscator() *Obfuscator {
	seed := make([]byte, 32)
	rand.Read(seed)
	return &Obfuscator{
		seed:       seed,
		mutations:  5,
		stringXor:  true,
		deadCode:   true,
	}
}

func (o *Obfuscator) Apply(srcDir string) error {
	fmt.Printf("obfuscator: seed=%x mutations=%d\n", o.seed[:8], o.mutations)
	if o.stringXor {
		o.xorStrings(srcDir)
	}
	if o.deadCode {
		o.insertDeadCode(srcDir)
	}
	return nil
}

func (o *Obfuscator) xorStrings(_ string) error  { return nil }
func (o *Obfuscator) insertDeadCode(_ string) error { return nil }
