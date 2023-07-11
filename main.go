package main

import (
	"fmt"
	"os"

	"github.com/awnumar/memguard"
)

func main() {
	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()

	// Purge the session when we return
	defer memguard.Purge()

	// Generate a key sealed inside an encrypted container
	key := memguard.NewEnclaveRandom(32)

	// Passing the key off to another function
	key = invert(key)

	// Decrypt the result returned from invert
	keyBuf, err := key.Open()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer keyBuf.Destroy()

	// Um output it
	fmt.Println(keyBuf.Bytes())
}

func invert(key *memguard.Enclave) *memguard.Enclave {
	// Decrypt the key into a local copy
	b, err := key.Open()
	if err != nil {
		memguard.SafePanic(err)
	}
	defer b.Destroy() // Destroy the copy when we return

	// Open returns the data in an immutable buffer, so make it mutable
	b.Melt()

	// Set every element to its complement
	for i := range b.Bytes() {
		b.Bytes()[i] = ^b.Bytes()[i]
	}

	// Return the new data in encrypted form
	return b.Seal() // <- sealing also destroys b
}