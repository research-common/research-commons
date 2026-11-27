package hdkey

import (
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// english.txt is the official BIP-39 English wordlist: 2048 lowercase ASCII words, one per line. The test
// checks its SHA-256 against the hash of the published file.
//
//go:embed english.txt
var englishRaw string

var (
	words   []string
	wordIdx map[string]int
)

func init() {
	words = strings.Split(strings.TrimSuffix(englishRaw, "\n"), "\n")
	if len(words) != 2048 {
		panic("hdkey: embedded wordlist is not 2048 words")
	}
	wordIdx = make(map[string]int, 2048)
	for i, w := range words {
		wordIdx[w] = i
	}
}

// Errors returned for a refused phrase or entropy. None carries phrase or entropy bytes.
var (
	ErrEntropyLength = errors.New("hdkey: entropy must be 16, 20, 24, 28 or 32 bytes")
	ErrWordCount     = errors.New("hdkey: a phrase has 12, 15, 18, 21 or 24 words")
	ErrNotASCII      = errors.New("hdkey: the phrase and passphrase must be ASCII (no Unicode normalisation is implemented)")
	ErrSpacing       = errors.New("hdkey: words are separated by exactly one space, with none at either end")
	ErrUnknownWord   = errors.New("hdkey: a word is not in the BIP-39 English list (lowercase only)")
	ErrBadChecksum   = errors.New("hdkey: the phrase's checksum does not match")
)

// EntropyToMnemonic encodes 16, 20, 24, 28 or 32 bytes of entropy as 12, 15, 18, 21 or 24 words. The checksum
// is the first len/4 bits of SHA-256 of the entropy.
func EntropyToMnemonic(entropy []byte) (string, error) {
	n := len(entropy)
	if n < 16 || n > 32 || n%4 != 0 {
		return "", ErrEntropyLength
	}
	sum := sha256.Sum256(entropy)
	bits := n * 8
	cs := bits / 32
	out := make([]string, (bits+cs)/11)
	for i := range out {
		idx := 0
		for b := 0; b < 11; b++ {
			pos := i*11 + b
			var bit byte
			if pos < bits {
				bit = entropy[pos/8] >> (7 - pos%8) & 1
			} else {
				p := pos - bits
				bit = sum[p/8] >> (7 - p%8) & 1
			}
			idx = idx<<1 | int(bit)
		}
		out[i] = words[idx]
	}
	return strings.Join(out, " "), nil
}

// ParseMnemonic checks a phrase and returns the entropy it encodes. It refuses, in this order: non-ASCII
// bytes (the English list is ASCII, and refusing avoids carrying a Unicode NFKD table), spacing other than one
// space between words, a word count other than 12/15/18/21/24, a word not in the list (the list is lowercase,
// so capitals are refused rather than folded), and a wrong checksum.
func ParseMnemonic(m string) ([]byte, error) {
	for i := 0; i < len(m); i++ {
		if m[i] >= 0x80 {
			return nil, ErrNotASCII
		}
	}
	if m == "" || m[0] == ' ' || m[len(m)-1] == ' ' || strings.Contains(m, "  ") || strings.ContainsAny(m, "\t\r\n") {
		return nil, ErrSpacing
	}
	ws := strings.Split(m, " ")
	if len(ws) < 12 || len(ws) > 24 || len(ws)%3 != 0 {
		return nil, ErrWordCount
	}
	total := len(ws) * 11
	buf := make([]byte, (total+7)/8)
	for i, w := range ws {
		idx, ok := wordIdx[w]
		if !ok {
			return nil, ErrUnknownWord
		}
		for b := 0; b < 11; b++ {
			if idx>>(10-b)&1 == 1 {
				pos := i*11 + b
				buf[pos/8] |= 1 << (7 - pos%8)
			}
		}
	}
	cs := total / 33
	entBytes := (total - cs) / 8
	ent := append([]byte(nil), buf[:entBytes]...)
	sum := sha256.Sum256(ent)
	for b := 0; b < cs; b++ {
		pos := entBytes*8 + b
		if buf[pos/8]>>(7-pos%8)&1 != sum[b/8]>>(7-b%8)&1 {
			Zero(ent)
			Zero(buf)
			return nil, ErrBadChecksum
		}
	}
	Zero(buf)
	return ent, nil
}

// Seed is PBKDF2-HMAC-SHA512 of the phrase with salt "mnemonic"+passphrase, 2048 rounds, 64 bytes. The phrase
// is checked first (ParseMnemonic). The passphrase argument exists so the published vectors, which use
// "TREZOR", can run; the tool always passes the empty string. A non-ASCII passphrase is refused because
// BIP-39 requires NFKD normalisation and none is implemented.
func Seed(mnemonic, passphrase string) ([]byte, error) {
	ent, err := ParseMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	Zero(ent)
	for i := 0; i < len(passphrase); i++ {
		if passphrase[i] >= 0x80 {
			return nil, ErrNotASCII
		}
	}
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+passphrase), 2048, 64, sha512.New), nil
}

// Zero overwrites b with zeros. Callers use it on seeds, entropy and keys when done.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
