package ledger

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/research-common/research-commons/internal/sig"
)

// The Ethereum app's APDUs (app-ethereum, doc/ethapp.adoc; unchanged across Nano S, S Plus, X, Flex, Stax).
const (
	claApp     = 0xb0 // the device OS's own commands, answered by any open app
	insAppVer  = 0x01 // get app name and version
	claEth     = 0xe0
	insAddress = 0x02 // get public key and address
	insSign    = 0x08 // sign personal message (EIP-191)

	p1Confirm    = 0x01 // show the address on the device and wait for the user
	p1NoConfirm  = 0x00
	p1FirstChunk = 0x00
	p1MoreChunks = 0x80

	// MaxChunk is the most data bytes one APDU carries (Lc is one byte).
	MaxChunk = 255
)

// EthereumApp is the name the Ethereum app reports.
const EthereumApp = "Ethereum"

// MaxMessage is the longest message this connector sends to the Ethereum app. The app keeps the whole message and a
// display copy of it in a 16 KiB heap (app-ethereum 1.23.0, src/utils/mem_utils.c) and refuses, after the last chunk,
// a message needing more than 255 review pages; a longer message is refused here before anything is sent. The app
// answers a message it cannot hold or show with a status word, which is mapped to the same failure, so the bound is
// a courtesy, not the check.
const MaxMessage = 7000

// App is what the device reports about the open app.
type App struct {
	Name, Version string
	// Flags is the raw flags byte string the device sent, for display; nil when none.
	Flags []byte
}

func exchange(t Transport, timeout time.Duration, apdu []byte, what string) ([]byte, error) {
	if to, ok := t.(Timeouter); ok {
		to.SetTimeout(timeout)
	}
	resp, err := t.Exchange(apdu)
	if err != nil {
		return nil, err
	}
	data, sw, err := split(resp)
	if err != nil {
		return nil, err
	}
	if sw != SWOK {
		return nil, swError(sw, what)
	}
	return data, nil
}

func apdu(cla, ins, p1, p2 byte, data []byte) []byte {
	return append([]byte{cla, ins, p1, p2, byte(len(data))}, data...)
}

// AppAndVersion asks the device which app is open. The dashboard answers too (as "BOLOS"), so this is how a caller
// tells "no app" from "another app" from "the Ethereum app".
func AppAndVersion(t Transport) (App, error) {
	data, err := exchange(t, ShortTimeout, apdu(claApp, insAppVer, 0, 0, nil), "read the open app")
	if err != nil {
		return App{}, err
	}
	bad := func(d string) (App, error) {
		return App{}, &Error{Slug: BadResponse, Detail: "the app-and-version answer is malformed: " + d}
	}
	// format (1, always 1), name length, name, version length, version, then optionally flags length and flags
	if len(data) < 3 || data[0] != 1 {
		return bad("no format byte 1")
	}
	n := int(data[1])
	if len(data) < 2+n+1 {
		return bad("the name runs past the end")
	}
	name := data[2 : 2+n]
	rest := data[2+n:]
	v := int(rest[0])
	if len(rest) < 1+v {
		return bad("the version runs past the end")
	}
	ver := rest[1 : 1+v]
	rest = rest[1+v:]
	var flags []byte
	if len(rest) > 0 {
		f := int(rest[0])
		if len(rest) != 1+f {
			return bad("the flags have the wrong length")
		}
		flags = append([]byte{}, rest[1:]...)
	}
	if !printable(name) || !printable(ver) {
		return bad("the name or version is not printable text")
	}
	return App{Name: string(name), Version: string(ver), Flags: flags}, nil
}

// Address asks the Ethereum app for the address at path. With confirm the device shows the address and waits for
// the user (a refusal is a Rejected failure). The address is recomputed from the public key the device returns and
// compared with the text it sent beside it; it is returned as 0x and 40 lowercase hex.
func Address(t Transport, path Path, confirm bool) (string, error) {
	p1, to := byte(p1NoConfirm), ShortTimeout
	if confirm {
		p1, to = p1Confirm, UserTimeout
	}
	data, err := exchange(t, to, apdu(claEth, insAddress, p1, 0, path.encode()), "show the address")
	if err != nil {
		return "", err
	}
	bad := func(d string) (string, error) {
		return "", &Error{Slug: BadResponse, Detail: "the address answer is malformed: " + d}
	}
	// public key length (65), uncompressed key, address length (40), address as ASCII hex without 0x
	if len(data) < 1 || data[0] != 65 || len(data) < 1+65+1 {
		return bad("no 65-byte public key")
	}
	pub, err := secp256k1.ParsePubKey(data[1:66])
	if err != nil {
		return bad("the public key is not a curve point")
	}
	rest := data[66:]
	if rest[0] != 40 || len(rest) < 41 {
		return bad("no 40-character address")
	}
	text := strings.ToLower(string(rest[1:41]))
	addr := hex.EncodeToString(sig.Address(pub))
	if text != addr {
		return bad("the address text is not the public key's address")
	}
	// trailing bytes: a chain code only when asked for (it is not)
	if len(rest) != 41 {
		return bad("unexpected bytes after the address")
	}
	return "0x" + addr, nil
}

// Chunks splits a personal-sign request into its APDU payloads: the first is the path, the message length as 4 bytes
// big-endian and as much of the message as fits in MaxChunk bytes; each next one carries up to MaxChunk more bytes.
// A message that fits in the first payload (including the empty one) is one APDU.
func Chunks(path Path, msg []byte) [][]byte {
	head := path.encode()
	n := len(msg)
	head = append(head, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	room := MaxChunk - len(head)
	if room > len(msg) {
		room = len(msg)
	}
	out := [][]byte{append(head, msg[:room]...)}
	for rest := msg[room:]; len(rest) > 0; {
		k := min(MaxChunk, len(rest))
		out = append(out, append([]byte{}, rest[:k]...))
		rest = rest[k:]
	}
	return out
}

// SignAPDUs is the whole personal-sign exchange as APDUs, in order.
func SignAPDUs(path Path, msg []byte) [][]byte {
	var out [][]byte
	for i, c := range Chunks(path, msg) {
		p1 := byte(p1FirstChunk)
		if i > 0 {
			p1 = p1MoreChunks
		}
		out = append(out, apdu(claEth, insSign, p1, 0, c))
	}
	return out
}

// PersonalSign streams msg to the Ethereum app for an EIP-191 personal_sign at path; the user reviews and approves
// on the device. It returns the signature in the stored encoding (r ‖ s ‖ v, low s, v 27 or 28): the device
// answers v ‖ r ‖ s, which is reordered and canonicalised here. It does not verify the signature: the caller does.
func PersonalSign(t Transport, path Path, msg []byte) ([]byte, error) {
	if len(msg) > MaxMessage {
		return nil, &Error{Slug: TooLong, Detail: "the message is " + itoa(len(msg)) + " bytes; this connector sends at most " + itoa(MaxMessage)}
	}
	reqs := SignAPDUs(path, msg)
	var data []byte
	for i, a := range reqs {
		to := ShortTimeout
		if i == len(reqs)-1 {
			to = UserTimeout // the last chunk's answer waits for the user's review
		}
		d, err := exchange(t, to, a, "sign the message")
		if err != nil {
			var e *Error
			if i == len(reqs)-1 && errors.As(err, &e) && e.SW == SWIncorrectData {
				// after the last chunk the app has the whole message; it refuses one needing more review pages than
				// it can show (app-ethereum: ui_191_message_fits) with this word
				return nil, &Error{Slug: TooLong, SW: e.SW, Detail: "the app refused the whole message: it needs more review pages than the app can show"}
			}
			return nil, err
		}
		if i < len(reqs)-1 && len(d) != 0 {
			return nil, &Error{Slug: BadResponse, Detail: "the device answered a message chunk with data"}
		}
		data = d
	}
	if len(data) != 65 {
		return nil, &Error{Slug: BadResponse, Detail: "the signature is " + itoa(len(data)) + " bytes, not 65"}
	}
	rsv := make([]byte, 65)
	copy(rsv, data[1:65])
	rsv[64] = data[0]
	c, ok := sig.Canonical(rsv)
	if !ok {
		return nil, &Error{Slug: BadResponse, Detail: "the device's answer is not a signature encoding"}
	}
	return c, nil
}

// MessageDisplay is how the Ethereum app shows msg for review: "text" when every byte is printable ASCII or white
// space (white space shown as a space on the Nano models), else "hex" (0x and the bytes in hex), as app-ethereum
// decides.
func MessageDisplay(msg []byte) string {
	for _, b := range msg {
		if !(b >= 0x20 && b <= 0x7e) && !(b >= 0x09 && b <= 0x0d) {
			return "hex"
		}
	}
	return "text"
}

func printable(b []byte) bool {
	return bytes.IndexFunc(b, func(r rune) bool { return r < 0x20 || r > 0x7e }) < 0
}

func itoa(n int) string { return strconv.Itoa(n) }
