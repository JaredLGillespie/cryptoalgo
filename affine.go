/*
Package affine provides functionality for decrypting, encrypting, and attacking jpg images.

For the attack, it uses the knowledge that a jpg binary file begins with 0xFF 0xD8, and uses this
knowledge to find the decryption key's a and b for (ax + b) % 256.
*/

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"strings"
)

func main() {
	methodType := flag.String("method", "", "The method to use: [decrypt, encrypt, attack].")
	inputFile := flag.String("input", "", "The input file.")
	outputFile := flag.String("output", "", "The output file.")
	aKey := flag.String("a", "", "The a key (only used for decrypt / encrypt).")
	bKey := flag.String("b", "", "The b key (only used for decrypt / encrypt).")

	flag.Parse()

	lowerMethodType := strings.ToLower(*methodType)

	inputBytes, err := ioutil.ReadFile(*inputFile)

	if err != nil {
		panic(fmt.Sprintf("Unable to read file %s: %s", *inputFile, err))
	}

	var a, b int
	if lowerMethodType == "decrypt" || lowerMethodType == "encrypt" {
		a, err = strconv.Atoi(*aKey)

		if err != nil {
			panic(fmt.Sprintf("%s: %s", "A valid a key must be provided for decrypt / encrypt methods", err))
		}

		b, err = strconv.Atoi(*bKey)

		if err != nil {
			panic(fmt.Sprintf("A valid b key must be provided for decrypt / encrypt methods: ", err))
		}
	}

	var outputBytes []byte
	switch lowerMethodType {
	case "decrypt":
		outputBytes = decrypt(inputBytes, a, b)
	case "encrypt":
		outputBytes = encrypt(inputBytes, a, b)
	case "attack":
		outputBytes = attack(inputBytes)
	default:
		panic("Invalid method provided, must be one of [decrypt, encrypt, attack]")
	}

	err = ioutil.WriteFile(*outputFile, outputBytes, 0644)

	if err != nil {
		panic(fmt.Sprintf("Unable to write file %s: %s", *outputFile, err))
	}
}

func encrypt(input []byte, a int, b int) []byte {
	output := make([]byte, 0, len(input))

	for _, c := range input {
		x := int(c)
		e := byte(mod(a*x+b, 256))
		output = append(output, e)
	}

	return output
}

func decrypt(input []byte, a int, b int) []byte {
	output := make([]byte, 0, len(input))
	aInv := int(big.NewInt(0).ModInverse(big.NewInt(int64(a)), big.NewInt(int64(256))).Int64())

	for _, c := range input {
		x := int(c)
		d := byte(mod(aInv*x-aInv*b, 256))
		output = append(output, d)
	}

	return output
}

func attack(input []byte) []byte {
	// First two bytes should be 0xFF and 0xD8,
	// which is 255 and 216 respectively
	y := int(input[0]) % 256
	z := int(input[1]) % 256

	a, b := -1, -1
	diffYZ := mod(y-z, 256)

	// Find a key
	for i := 0; i < 256; i++ {
		if diffYZ == mod(39*i, 256) { // (39 = 255 - 216)
			if gcd(256, i) == 1 {
				a = i
			}
		}
	}

	// Find b key
	for i := 0; i < 256; i++ {
		if (255*a+i)%256 == y {
			b = i
		}
	}

	if a == -1 || b == -1 {
		panic("Unable to find encryption keys!")
	}

	fmt.Printf("a is %d, b is %d\n", a, b)

	return decrypt(input, a, b)
}

// gcd returns the greatest common devisor between a and b
func gcd(a, b int) int {
	for a != b {
		if a > b {
			a -= b
		} else {
			b -= a
		}
	}

	return a
}

// mod returns the positive version of a % z
func mod(a, z int) int {
	r := a % z
	if r < 0 {
		r = z + r
	}
	return r
}
