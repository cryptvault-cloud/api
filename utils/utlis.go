package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"hash"
	"io"
	"strconv"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func getCryptoRandVec(rand io.Reader, length int) []byte {
	out := make([]byte, length)
	_, err := io.ReadFull(rand, out)
	check(err)
	return out
}

func to32ByteArray(in []byte) *[32]byte {
	if len(in) != 32 {
		panic("Input array size does not match. Expected 32, but got " + strconv.Itoa(len(in)))
	}
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = in[i]
	}

	return &out
}

func to16ByteArray(in []byte) *[16]byte {
	if len(in) != 16 {
		panic("Input array size does not match. Expected 16, but got " + strconv.Itoa(len(in)))
	}
	var out [16]byte
	for i := 0; i < 16; i++ {
		out[i] = in[i]
	}

	return &out
}

func decryptSymmetric(in, key []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)

	cipher := cipher.NewCTR(block, in[:aes.BlockSize])

	out := make([]byte, len(in)-aes.BlockSize)
	cipher.XORKeyStream(out, in[aes.BlockSize:])

	return out
}

// Key-Derivation Function.
func kdf(hash hash.Hash, shared, s1 []byte) []byte {
	hash.Write(shared)
	if s1 != nil {
		hash.Write(s1)
	}
	key := hash.Sum(nil)
	hash.Reset()
	return key
}

func verifyTag(mac *[16]byte, in, shared []byte, key *[32]byte) bool {
	macF := hmac.New(sha512.New, key[:])
	macF.Write(append(in, shared...))
	calculated := macF.Sum(nil)
	m := mac[:]
	return hmac.Equal(m, calculated[:16])
}

func sumTag(in, shared []byte, key *[32]byte) [16]byte {
	macF := hmac.New(sha512.New, key[:])
	macF.Write(append(in, shared...))
	calculated := macF.Sum(nil)
	var ret [16]byte
	copy(ret[:], calculated)
	return ret
}

func encryptSymmetric(rand io.Reader, in, key []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)

	nonce := getCryptoRandVec(rand, aes.BlockSize)
	cipher := cipher.NewCTR(block, nonce)

	out := make([]byte, len(in))

	cipher.XORKeyStream(out, in)

	out = append(nonce, out...)
	return out
}
