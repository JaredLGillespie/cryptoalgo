/*
Package rdes provides functionality for decryption and encryption using a reduced DES protocol.

Usage:
	-x string
		(REQUIRED) The input string.
	-k string
		(REQUIRED) 12-bit key string represented as 3 hex characters (ex. AE3).
	-m method
	    (REQUIRED) 0 for encryption, 1 for decryption.
	-o string
		(OPTIONAL) The output file (defaults to console if not specified).
	-f
		(OPTIONAL) Flags that the input string is a file path.
*/

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"
)

func main() {
	// Command-line parsing
	inputString := flag.String("x", "", "The input string.")
	keyString := flag.String("k", "", "The 12-bit encryption / decryption key.")
	methodType := flag.Int("m", 0, "The method to use: [0: encryption, 1: decryption].")
	outputFile := flag.String("o", "", "The output file (defaults to console if not specified).")
	isFile := flag.Bool("f", false, "The a key (only used for decrypt / encrypt).")

	flag.Parse()

	// Interpret input string
	if len(*inputString) == 0 {
		panic("No input given")
	}

	inputBytes := []byte(*inputString)
	var err error

	if *isFile {
		inputBytes, err = ioutil.ReadFile(*inputString)
		if err != nil {
			panic(fmt.Sprintf("Unable to read file %s: %s", *inputString, err))
		}
	}

	// Interpret key string
	if len(*keyString) != 3 {
		panic("Unable to interpret 12-bit key, must be 3 hexadecimal characters (0 - F)")
	}

	key, err := strconv.ParseUint(*keyString, 16, 12)

	if err != nil {
		panic(fmt.Sprintf("%s: %s", "Unable to interpret 12-bit key", err))
	}

	// Perform the things
	var outputBytes []byte

	tic := time.Now()

	k1, k2, k3 := keyScheduler(key)

	print(fmt.Sprintf("Keys: %X %X %X\n", int(k1), int(k2), int(k3)))

	if *methodType == 0 {
		outputBytes = encrypt(inputBytes, k1, k2, k3)
	} else if *methodType == 1 {
		outputBytes = decrypt(inputBytes, k1, k2, k3)
	} else {
		panic(fmt.Sprintf("Method type must be 0 [encryption] or 1 [decryption] , but %d given", *methodType))
	}

	if len(*outputFile) > 0 {
		if err = ioutil.WriteFile(*outputFile, outputBytes, 0644); err != nil {
			panic(fmt.Sprintf("Unable to write file %s: %s", *outputFile, err))
		}
	} else {
		print(fmt.Sprintf("Output: %s\n", outputBytes))
	}

	toc := time.Now()

	print(fmt.Sprintf("Runtime (s): %f\n", toc.Sub(tic).Seconds()))
}

// encrypt encrypts an array of bytes
func encrypt(input []byte, k1 byte, k2 byte, k3 byte) []byte {
	output := make([]byte, 0, len(input))

	for byt := 0; byt < len(input); byt++ {
		eb := encryptByte(input[byt], k1, k2, k3)
		output = append(output, eb)
	}

	return output
}

// encryptByte encrypts a single byte
func encryptByte(input byte, k1 byte, k2 byte, k3 byte) byte {
	l := input >> 4                          // Leftmost four bits (shifted to lower-half)
	r := input & (1<<0 | 1<<1 | 1<<2 | 1<<3) // Rightmost four bits

	for rnd := 0; rnd < 3; rnd++ {
		l, r = r, f(r, k1, k2, k3, rnd)^l
	}

	return r<<4 | l
}

// decrypt decrypts an array of bytes
func decrypt(input []byte, k1 byte, k2 byte, k3 byte) []byte {
	output := make([]byte, 0, len(input))

	for byt := 0; byt < len(input); byt++ {
		eb := decryptByte(input[byt], k1, k2, k3)
		output = append(output, eb)
	}

	return output
}

// decryptByte decrypts a single byte
func decryptByte(input byte, k1 byte, k2 byte, k3 byte) byte {
	l := input >> 4                          // Leftmost four bits (shifted to lower-half)
	r := input & (1<<0 | 1<<1 | 1<<2 | 1<<3) // Rightmost four bits

	for rnd := 2; rnd > -1; rnd-- {
		l, r = r, f(r, k1, k2, k3, rnd)^l
	}

	return r<<4 | l
}

// f is the magic function used in the encryption
func f(input byte, k1 byte, k2 byte, k3 byte, round int) byte {
	if round == 0 {
		return input ^ k1
	} else if round == 1 {
		return input ^ k2
	} else {
		return input ^ k3
	}
}

// keyScheduler returns the 3 4-bit round keys
func keyScheduler(key uint64) (byte, byte, byte) {
	k1to4 := byte((key & (1<<8 | 1<<9 | 1<<10 | 1<<11)) >> 8)
	k5to8 := byte((key & (1<<4 | 1<<5 | 1<<6 | 1<<7)) >> 4)
	k9to12 := byte((key & (1<<0 | 1<<1 | 1<<2 | 1<<3)) >> 0)

	return k1to4 ^ k5to8, k5to8 ^ k9to12, k9to12 ^ k1to4
}
