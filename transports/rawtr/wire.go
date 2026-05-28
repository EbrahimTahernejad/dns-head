package rawtr

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
	"io"
)

// Wire frame, post-DNS-header:
//
//   [12B nonce][AEAD body][16B AEAD tag]
//
// Body (decrypted):
//
//   [1B type][type-specific payload]
//
// types:
//   0x01 SYN     [4B clientConnID][8B clientInitSeq]
//   0x02 SYNACK  [4B clientConnID][8B serverInitSeq]
//   0x03 DATA    [4B seq][2B len][payload]
//   0x04 ACK     [4B ackUpTo]
//   0x05 FIN     (no body)
//   0x06 PING    [8B ts]
//   0x07 PONG    [8B ts]

const (
	tSYN    = 0x01
	tSYNACK = 0x02
	tDATA   = 0x03
	tACK    = 0x04
	tFIN    = 0x05
	tPING   = 0x06
	tPONG   = 0x07
)

const nonceLen = chacha20poly1305.NonceSize

// deriveKey turns the PSK into a 32-byte chacha20-poly1305 key.
func deriveKey(psk string) ([]byte, error) {
	r := hkdf.New(sha256.New, []byte(psk), []byte("dns-head-raw-v1"), nil)
	k := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, err
	}
	return k, nil
}

func newAEAD(psk string) (cipher.AEAD, error) {
	k, err := deriveKey(psk)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(k)
}

// seal returns nonce||ciphertext for body. Allocates.
func seal(aead cipher.AEAD, body []byte) []byte {
	out := make([]byte, nonceLen+len(body)+aead.Overhead())
	if _, err := rand.Read(out[:nonceLen]); err != nil {
		panic(err) // crypto/rand only fails catastrophically
	}
	aead.Seal(out[nonceLen:nonceLen], out[:nonceLen], body, nil)
	return out
}

// open returns the decrypted body or an error.
func open(aead cipher.AEAD, frame []byte) ([]byte, error) {
	if len(frame) < nonceLen+aead.Overhead() {
		return nil, errors.New("rawtr: frame too short")
	}
	nonce := frame[:nonceLen]
	ct := frame[nonceLen:]
	return aead.Open(ct[:0], nonce, ct, nil)
}

// putUint32 / readUint32 helpers, kept inline to avoid an alloc.
func putU32(b []byte, off int, v uint32) { binary.BigEndian.PutUint32(b[off:], v) }
func getU32(b []byte, off int) uint32    { return binary.BigEndian.Uint32(b[off:]) }
func putU16(b []byte, off int, v uint16) { binary.BigEndian.PutUint16(b[off:], v) }
func getU16(b []byte, off int) uint16    { return binary.BigEndian.Uint16(b[off:]) }
