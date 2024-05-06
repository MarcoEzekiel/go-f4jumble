// This Package provides a mechanism for "jumbling" byte slices in a reversible way.
//
// Many byte encodings such as [Base64] and [Bech32] do not have "cascading" behaviour:
// changing an input byte at one position has no effect on the encoding of bytes at
// distant positions. This can be a problem if users generally check the correctness of
// encoded strings by eye, as they will tend to only check the first and/or last few
// characters of the encoded string. In some situations (for example, a hardware device
// displaying on its screen an encoded string provided by an untrusted computer), it is
// potentially feasible for an adversary to change some internal portion of the encoded
// string in a way that is beneficial to them, without the user noticing.
//
// The function F4Jumble (and its inverse function, F4Jumble⁻¹) are length-preserving
// transformations can be used to trivially introduce cascading behaviour to existing
// encodings:
// - Prepare the raw `message` bytes.
// - Pass `message` through [F4jumble] to obtain the jumbled bytes.
// - Encode the jumbled bytes with the encoding scheme.
//
// Changing any byte of `message` will result in a completely different sequence of
// jumbled bytes. Specifically, F4Jumble uses an unkeyed 4-round Feistel construction to
// approximate a random permutation.
//
// [Diagram of 4-round unkeyed Feistel construction](https://zips.z.cash/zip-0316-f4.png)
//
// [Base64]: https://en.wikipedia.org/wiki/Base64
// [Bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#Bech32
package f4jumble

import (
	"errors"

	"github.com/gtank/blake2/blake2b"
)

// Minimum and maximum message lengths
const (
	minLenM = 48
	maxLenM = 4194368
	lenH    = 64
)

func ceilDiv(num int, den int) int {
	return (num + den - 1) / den
}

func hPers(i int) []byte {
	return []byte{85, 65, 95, 70, 52, 74, 117, 109, 98, 108, 101, 95, 72, uint8(i), 0, 0}
}

func gPers(i int, j int) []byte {
	return []byte{85, 65, 95, 70, 52, 74, 117, 109, 98, 108, 101, 95, 71, uint8(i), uint8(j & 0xff), uint8(j >> 8)}
}

// XOR returns the exclusive OR of two byte slices
func xor(x, y []byte) []byte {
	result := make([]byte, len(x))
	for i := range x {
		if i <= len(y) {
			result[i] = x[i] ^ y[i]
		}
	}
	return result
}

func gRound(i int, u []byte, lenR int) ([]byte, error) {
	inner := func(j int) ([]byte, error) {
		g, err := blake2b.NewDigest(nil, nil, gPers(i, j), lenH)
		if err != nil {
			return nil, err
		}
		g.Write(u)
		return g.Sum(nil), nil
	}

	var result []byte
	for j := 0; j < ceilDiv(lenR, lenH); j++ {
		hash, err := inner(j)
		if err != nil {
			return nil, err
		}
		result = append(result, hash...)
	}
	return result[:lenR], nil
}

func hRound(i int, u []byte, lenL int) ([]byte, error) {
	h, err := blake2b.NewDigest(nil, nil, hPers(i), lenL)
	if err != nil {
		return nil, err
	}

	h.Write(u)
	return h.Sum(nil), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Encodes the given []byte using F4Jumble, and returns the encoded message as []byte.
// Returns an error if the message is an invalid length.
//
// # Examples
//
//	src := []byte{
//		0x5d, 0x7a, 0x8f, 0x73, 0x9a, 0x2d, 0x9e, 0x94, 0x5b, 0x0c, 0xe1, 0x52, 0xa8, 0x04, 0x9e, 0x29, 0x4c, 0x4d, 0x6e, 0x66, 0xb1, 0x64, 0x93, 0x9d, 0xaf, 0xfa, 0x2e, 0xf6, 0xee, 0x69, 0x21, 0x48, 0x1c, 0xdd, 0x86, 0xb3, 0xcc, 0x43, 0x18, 0xd9, 0x61, 0x4f, 0xc8, 0x20, 0x90, 0x5d, 0x04, 0x2b,
//	}
//	jumbled := []byte{
//		0x03, 0x04, 0xd0, 0x29, 0x14, 0x1b, 0x99, 0x5d, 0xa5, 0x38, 0x7c, 0x12, 0x59, 0x70, 0x67, 0x35, 0x04, 0xd6, 0xc7, 0x64, 0xd9, 0x1e, 0xa6, 0xc0, 0x82, 0x12, 0x37, 0x70, 0xc7, 0x13, 0x9c, 0xcd, 0x88, 0xee, 0x27, 0x36, 0x8c, 0xd0, 0xc0, 0x92, 0x1a, 0x04, 0x44, 0xc8, 0xe5, 0x85, 0x8d, 0x22,
//	}
//
//	jumbledSrc, f4JumbleError := F4Jumble(src)
//
//	if f4JumbleError == nil && bytes.Equal(jumbled, jumbledSrc){
//		// It Worked!
//	}
func F4Jumble(M []byte) ([]byte, error) {
	//println("M:", hex.EncodeToString(M)[:20])
	lenM := len(M)
	if lenM < minLenM || lenM > maxLenM {
		return nil, errors.New("invalid message length")
	}

	lenL := min(lenH, lenM/2)
	lenR := lenM - lenL

	a := M[:lenL]
	b := M[lenL:]

	g0, err := gRound(0, a, lenR)
	if err != nil {
		return nil, err
	}
	x := xor(b, g0)

	h0, err := hRound(0, x, lenL)
	if err != nil {
		return nil, err
	}
	y := xor(a, h0)

	g1, err := gRound(1, y, lenR)
	if err != nil {
		return nil, err
	}
	d := xor(x, g1)

	h1, err := hRound(1, d, lenL)
	if err != nil {
		return nil, err
	}
	c := xor(y, h1)

	return append(c, d...), nil
}

// Inverts the F4Jumble operation, returning the original un-jumbled bytes.
// Returns an error if the message is an invalid length.
//
// # Examples
//
//	src := []byte{
//		0x5d, 0x7a, 0x8f, 0x73, 0x9a, 0x2d, 0x9e, 0x94, 0x5b, 0x0c, 0xe1, 0x52, 0xa8, 0x04, 0x9e, 0x29, 0x4c, 0x4d, 0x6e, 0x66, 0xb1, 0x64, 0x93, 0x9d, 0xaf, 0xfa, 0x2e, 0xf6, 0xee, 0x69, 0x21, 0x48, 0x1c, 0xdd, 0x86, 0xb3, 0xcc, 0x43, 0x18, 0xd9, 0x61, 0x4f, 0xc8, 0x20, 0x90, 0x5d, 0x04, 0x2b,
//		}
//	jumbled := []byte{
//		0x03, 0x04, 0xd0, 0x29, 0x14, 0x1b, 0x99, 0x5d, 0xa5, 0x38, 0x7c, 0x12, 0x59, 0x70, 0x67, 0x35, 0x04, 0xd6, 0xc7, 0x64, 0xd9, 0x1e, 0xa6, 0xc0, 0x82, 0x12, 0x37, 0x70, 0xc7, 0x13, 0x9c, 0xcd, 0x88, 0xee, 0x27, 0x36, 0x8c, 0xd0, 0xc0, 0x92, 0x1a, 0x04, 0x44, 0xc8, 0xe5, 0x85, 0x8d, 0x22,
//	}
//
//	unJumbled, unJumbleError := F4JumbleInv(jumbled)
//
//	if unJumbleError == nil && bytes.Equal(unJumbled,src){
//		// It Worked!
//	}
func F4JumbleInv(M []byte) ([]byte, error) {
	lenM := len(M)
	if lenM < minLenM || lenM > maxLenM {
		return nil, errors.New("invalid message length")
	}
	lenL := min(lenH, lenM/2)
	lenR := lenM - lenL

	c := M[:lenL]
	d := M[lenL:]

	h1, err := hRound(1, d, lenL)
	if err != nil {
		return nil, err
	}
	y := xor(c, h1)

	g1, err := gRound(1, y, lenR)
	if err != nil {
		return nil, err
	}
	x := xor(d, g1)

	h0, err := hRound(0, x, lenL)
	if err != nil {
		return nil, err
	}
	a := xor(y, h0)

	g0, err := gRound(0, a, lenR)
	if err != nil {
		return nil, err
	}
	b := xor(x, g0)

	return append(a, b...), nil
}
