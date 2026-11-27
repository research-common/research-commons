package hdkey

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/ledger"
)

// The module bans encoding/json for received bytes; test data is read with the module's own reader.
func load(t *testing.T, name string) canon.Value {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	v, err := canon.Parse(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

func path(t *testing.T, s string) ledger.Path {
	t.Helper()
	p, err := ledger.ParsePath(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWordlistHash(t *testing.T) {
	// SHA-256 of english.txt as published in the BIP-39 repository (bip-0039/english.txt), 2048 lines.
	const want = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	sum := sha256.Sum256([]byte(englishRaw))
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("wordlist hash %s", got)
	}
	file, err := os.ReadFile("testdata/bip39-english.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(file) != englishRaw {
		t.Fatal("wordlist.go differs from testdata/bip39-english.txt")
	}
	for i := 1; i < len(words); i++ {
		if words[i-1] >= words[i] {
			t.Fatal("wordlist not strictly sorted")
		}
	}
}

func obj(t *testing.T, v canon.Value) *canon.Object {
	t.Helper()
	o, ok := v.(*canon.Object)
	if !ok {
		t.Fatalf("not an object: %T", v)
	}
	return o
}

func field(t *testing.T, o *canon.Object, k string) canon.Value {
	t.Helper()
	v, ok := o.Get(k)
	if !ok {
		t.Fatalf("missing %q", k)
	}
	return v
}

func str(t *testing.T, v canon.Value) string {
	t.Helper()
	s, ok := v.(canon.String)
	if !ok {
		t.Fatalf("not a string: %T", v)
	}
	return string(s)
}

const b58alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// xprvKey decodes a Base58Check extended private key and returns its chain code and private key. The tool
// has no xprv code; this is only so the test can compare against the BIP-32 vectors' published strings. It
// also checks the 4-byte double-SHA-256 checksum.
func xprvKey(t *testing.T, s string) (chain, key []byte) {
	t.Helper()
	n := new(big.Int)
	for _, c := range s {
		i := strings.IndexRune(b58alphabet, c)
		if i < 0 {
			t.Fatalf("bad base58 char in vector")
		}
		n.Mul(n, big.NewInt(58))
		n.Add(n, big.NewInt(int64(i)))
	}
	b := n.FillBytes(make([]byte, 82))
	h1 := sha256.Sum256(b[:78])
	h2 := sha256.Sum256(h1[:])
	if !bytes.Equal(h2[:4], b[78:]) {
		t.Fatal("vector xprv checksum")
	}
	if !bytes.Equal(b[:4], []byte{0x04, 0x88, 0xAD, 0xE4}) || b[45] != 0 {
		t.Fatal("vector is not a mainnet xprv")
	}
	return b[13:45], b[46:78]
}

func TestBIP39Vectors(t *testing.T) {
	root := obj(t, load(t, "bip39-trezor-vectors.json"))
	list, ok := field(t, root, "english").(canon.Array)
	if !ok || len(list) != 24 {
		t.Fatalf("expected 24 official English vectors, got %d", len(list))
	}
	for n, e := range list {
		row := e.(canon.Array)
		ent, _ := hex.DecodeString(str(t, row[0]))
		phrase, wantSeed := str(t, row[1]), str(t, row[2])
		got, err := EntropyToMnemonic(ent)
		if err != nil || got != phrase {
			t.Fatalf("vector %d: entropy to mnemonic: %v", n, err)
		}
		back, err := ParseMnemonic(phrase)
		if err != nil || !bytes.Equal(back, ent) {
			t.Fatalf("vector %d: mnemonic to entropy: %v", n, err)
		}
		seed, err := Seed(phrase, "TREZOR")
		if err != nil || hex.EncodeToString(seed) != wantSeed {
			t.Fatalf("vector %d: seed: %v", n, err)
		}
		m, err := Master(seed)
		if err != nil {
			t.Fatal(err)
		}
		chain, key := xprvKey(t, str(t, row[3]))
		if !bytes.Equal(m.Private(), key) || !bytes.Equal(m.ChainCode(), chain) {
			t.Fatalf("vector %d: master key differs from the vector's xprv", n)
		}
	}
}

func TestBIP32Vectors(t *testing.T) {
	root := obj(t, load(t, "bip32-vectors.json"))
	vecs := field(t, root, "vectors").(canon.Array)
	if len(vecs) != 4 {
		t.Fatalf("vectors 1-4 expected, got %d", len(vecs))
	}
	checked := 0
	for _, e := range vecs {
		v := obj(t, e)
		seed, _ := hex.DecodeString(str(t, field(t, v, "seed")))
		m, err := Master(seed)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range field(t, v, "chains").(canon.Array) {
			co := obj(t, c)
			p := str(t, field(t, co, "path"))
			chain, key := xprvKey(t, str(t, field(t, co, "xprv")))
			pp := ledger.Path{}
			if p != "m" {
				pp = path(t, p)
			}
			k, err := m.Derive(pp)
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			if !bytes.Equal(k.Private(), key) || !bytes.Equal(k.ChainCode(), chain) {
				t.Fatalf("%s: key or chain code differs", p)
			}
			checked++
		}
	}
	if checked != 17 {
		t.Fatalf("checked %d chains, want 17", checked)
	}
}

func TestEthereumAddresses(t *testing.T) {
	root := obj(t, load(t, "eth-vectors.json"))
	for _, e := range field(t, root, "vectors").(canon.Array) {
		v := obj(t, e)
		k, err := DeriveFromMnemonic(str(t, field(t, v, "mnemonic")), "", path(t, str(t, field(t, v, "path"))))
		if err != nil {
			t.Fatal(err)
		}
		got := hex.EncodeToString(k.Address())
		if !strings.EqualFold(got, str(t, field(t, v, "address"))) {
			t.Fatalf("%s %s: got %s", str(t, field(t, v, "source")), str(t, field(t, v, "path")), got)
		}
	}
}

func TestRoundTripAllSizes(t *testing.T) {
	for _, n := range []int{16, 20, 24, 28, 32} {
		for i := 0; i < 50; i++ {
			ent := make([]byte, n)
			rand.Read(ent)
			m, err := EntropyToMnemonic(ent)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(strings.Split(m, " ")); got != (n*8+n*8/32)/11 {
				t.Fatalf("%d bytes gave %d words", n, got)
			}
			back, err := ParseMnemonic(m)
			if err != nil || !bytes.Equal(back, ent) {
				t.Fatalf("round trip %d bytes: %v", n, err)
			}
		}
	}
}

// Changing one word of a valid phrase keeps the checksum valid only when the new word's checksum bits happen
// to match: probability 2^-cs for a phrase with cs checksum bits (4 for 12 words, 8 for 24), apart from the
// last word, which carries both entropy and checksum bits. The test fixes the phrases, tries every
// replacement for one position and checks the count of accepted ones is within what that probability allows.
func TestSingleWordChangeMostlyFails(t *testing.T) {
	for _, n := range []int{16, 32} {
		ent := bytes.Repeat([]byte{0x5a}, n)
		m, _ := EntropyToMnemonic(ent)
		ws := strings.Split(m, " ")
		accepted := 0
		for _, w := range words {
			if w == ws[0] {
				continue
			}
			c := append([]string{w}, ws[1:]...)
			if _, err := ParseMnemonic(strings.Join(c, " ")); err == nil {
				accepted++
			}
		}
		// 2047 alternatives; expected 2047/2^cs accepted (cs = 4 or 8), allow up to double that.
		cs := n * 8 / 32
		limit := 2 * 2047 >> cs
		if accepted > limit {
			t.Fatalf("%d bytes: %d replacements accepted, limit %d", n, accepted, limit)
		}
		if accepted == 0 && n == 16 {
			t.Fatalf("expected some accepted replacements at 4 checksum bits")
		}
	}
}

func TestRefusals(t *testing.T) {
	good := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	cases := []struct {
		name, in string
		want     error
	}{
		{"empty", "", ErrSpacing},
		{"eleven words", strings.TrimSuffix(good, " about"), ErrWordCount},
		{"thirteen words", good + " about", ErrWordCount},
		{"unknown word", strings.Replace(good, "about", "abouts", 1), ErrUnknownWord},
		{"capital letter", strings.Replace(good, "about", "About", 1), ErrUnknownWord},
		{"bad checksum", strings.Replace(good, "about", "abandon", 1), ErrBadChecksum},
		{"non-ASCII", strings.Replace(good, "about", "abo\u00fct", 1), ErrNotASCII},
		{"non-ASCII lookalike", strings.Replace(good, "about", "abou\u0074", 1), nil},
		{"double space", strings.Replace(good, "abandon abandon", "abandon  abandon", 1), ErrSpacing},
		{"leading space", " " + good, ErrSpacing},
		{"trailing space", good + " ", ErrSpacing},
		{"tab", strings.Replace(good, "abandon abandon", "abandon\tabandon", 1), ErrSpacing},
		{"newline", good + "\n", ErrSpacing},
	}
	for _, c := range cases {
		_, err := ParseMnemonic(c.in)
		if err != c.want {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	for _, n := range []int{0, 15, 17, 33, 36} {
		if _, err := EntropyToMnemonic(make([]byte, n)); err != ErrEntropyLength {
			t.Errorf("%d bytes: %v", n, err)
		}
	}
	if _, err := Seed(good, "p\u00e4ss"); err != ErrNotASCII {
		t.Errorf("non-ASCII passphrase: %v", err)
	}
	if _, err := Seed("abandon", ""); err != ErrWordCount {
		t.Errorf("Seed must check the phrase: %v", err)
	}
	if _, err := Master(make([]byte, 15)); err != ErrSeedLength {
		t.Errorf("short seed: %v", err)
	}
	if _, err := Master(make([]byte, 65)); err != ErrSeedLength {
		t.Errorf("long seed: %v", err)
	}
}

func TestSecretsNotFormatted(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	k, _ := Master(seed)
	hexKey := hex.EncodeToString(k.Private())
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d"} {
		if out := fmt.Sprintf(f, k); strings.Contains(out, hexKey) || strings.Contains(out, hexKey[:16]) {
			t.Errorf("%s printed key material", f)
		}
	}
	ent := bytes.Repeat([]byte{1}, 16)
	m, _ := EntropyToMnemonic(ent)
	_, err := ParseMnemonic(strings.Replace(m, "abandon", "zzz", 1) + " x")
	if err != nil && strings.Contains(err.Error(), m[:20]) {
		t.Error("error repeats the phrase")
	}
}

func TestZero(t *testing.T) {
	k, _ := Master(bytes.Repeat([]byte{9}, 32))
	k.Zero()
	if !bytes.Equal(k.Private(), make([]byte, 32)) || !bytes.Equal(k.ChainCode(), make([]byte, 32)) {
		t.Fatal("Zero left bytes")
	}
	b := []byte{1, 2, 3}
	Zero(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Fatal("Zero(b)")
	}
}

func TestDeriveDoesNotAliasOrDestroyParent(t *testing.T) {
	m, _ := Master(bytes.Repeat([]byte{3}, 32))
	before := m.Private()
	c, err := m.Derive(path(t, "m/44'/60'/0'/0/0"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Private(), before) {
		t.Fatal("parent changed")
	}
	same, _ := m.Derive(ledger.Path{})
	same.Zero()
	if !bytes.Equal(m.Private(), before) {
		t.Fatal("zeroing an empty-path copy zeroed the parent")
	}
	_ = c
}

// The spec's invalid-key cases cannot be reached through a real seed (probability below 2^-127), so they are
// tested on the step that handles the HMAC output directly.
func TestInvalidKeyCases(t *testing.T) {
	n, _ := hex.DecodeString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	i := append(append([]byte(nil), n...), make([]byte, 32)...)
	if _, err := fromI(i, nil); err != ErrInvalidKey {
		t.Errorf("IL = n: %v", err)
	}
	// IL = n+1 would reduce to the valid key 1 if the overflow were ignored.
	np1 := append([]byte(nil), n...)
	np1[31]++
	if _, err := fromI(append(np1, make([]byte, 32)...), nil); err != ErrInvalidKey {
		t.Errorf("IL = n+1: %v", err)
	}
	if _, err := fromI(make([]byte, 64), nil); err != ErrInvalidKey {
		t.Errorf("IL = 0 as a master key: %v", err)
	}
	// IL = n-1 plus a parent key of 1 gives n = 0 mod n: the child key is zero.
	nm1 := append([]byte(nil), n...)
	nm1[31]--
	var one [32]byte
	one[31] = 1
	var par secp256k1.ModNScalar
	par.SetBytes(&one)
	if _, err := fromI(append(nm1, make([]byte, 32)...), &par); err != ErrInvalidKey {
		t.Errorf("child key zero: %v", err)
	}
}
