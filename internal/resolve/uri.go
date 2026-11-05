package resolve

import (
	"strings"
)

// URI comparison for completeness scopes (wire §5 `edition.contents.completeness`): an endpoint, or an
// instrument that is an absolute URI, is compared after RFC 3986 §6.2.2 syntax-based normalization of both
// sides, plus the one scheme-based rule every http(s) reader applies (§6.2.3: an empty path with an authority
// is `/`, the scheme's default port is dropped). Two values that differ under that normalization but agree
// once a trailing `/` is dropped and every percent-encoding is decoded may or may not name one resource
// (RFC 3986 §6.2.2.2: `%2F` is not `/`; a trailing slash is a different path), so the comparison reports them
// as undecided, never as different.

// uriMatch is the outcome of comparing a reading's source with a claim's.
type uriMatch int

const (
	uriDiffer uriMatch = iota // out of scope
	uriEqual                  // the same source
	uriLoose                  // equal only once a trailing `/` or a percent-encoding is set aside: undecided
)

// compareSource compares two source values: as URIs when both are absolute URIs, else as strings.
func compareSource(a, b string) uriMatch {
	if a == b {
		return uriEqual
	}
	na, oka := normURI(a)
	nb, okb := normURI(b)
	if !oka || !okb {
		return uriDiffer
	}
	if na == nb {
		return uriEqual
	}
	if looseURI(na) == looseURI(nb) {
		return uriLoose
	}
	return uriDiffer
}

var defaultPort = map[string]string{"http": "80", "https": "443"}

// normURI normalizes an absolute URI (RFC 3986 §3: scheme ":" hier-part) by §6.2.2: scheme and host lower
// case, percent-encodings in upper case with unreserved characters decoded, dot segments removed; and for a
// URI with an authority, the scheme's default port dropped and an empty path read as `/` (§6.2.3). ok is
// false for anything that is not an absolute URI, which is then compared as text.
func normURI(s string) (string, bool) {
	i := strings.IndexByte(s, ':')
	if i < 1 || !isScheme(s[:i]) {
		return "", false
	}
	scheme, rest := strings.ToLower(s[:i]), s[i+1:]
	frag, hasFrag := "", false
	if j := strings.IndexByte(rest, '#'); j >= 0 {
		rest, frag, hasFrag = rest[:j], rest[j+1:], true
	}
	query, hasQuery := "", false
	if j := strings.IndexByte(rest, '?'); j >= 0 {
		rest, query, hasQuery = rest[:j], rest[j+1:], true
	}
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteByte(':')
	path := rest
	if strings.HasPrefix(rest, "//") {
		auth := rest[2:]
		path = ""
		if j := strings.IndexByte(auth, '/'); j >= 0 {
			auth, path = auth[:j], auth[j:]
		}
		userinfo, host := "", auth
		if j := strings.LastIndexByte(auth, '@'); j >= 0 {
			userinfo, host = auth[:j+1], auth[j+1:]
		}
		port := ""
		if j := strings.LastIndexByte(host, ':'); j >= 0 && !strings.Contains(host[j:], "]") {
			host, port = host[:j], host[j+1:]
		}
		if port == "" || port == defaultPort[scheme] {
			port = ""
		}
		b.WriteString("//")
		b.WriteString(pctNorm(userinfo))
		b.WriteString(strings.ToLower(pctNorm(host)))
		if port != "" {
			b.WriteByte(':')
			b.WriteString(port)
		}
		if path == "" {
			path = "/"
		}
	}
	b.WriteString(removeDots(pctNorm(path)))
	if hasQuery {
		b.WriteByte('?')
		b.WriteString(pctNorm(query))
	}
	if hasFrag {
		b.WriteByte('#')
		b.WriteString(pctNorm(frag))
	}
	return b.String(), true
}

// looseURI is a normalized URI with every percent-encoding decoded and trailing slashes dropped from its path:
// the comparison that says two spellings might name one resource, used only to mark a match undecided.
func looseURI(n string) string {
	end := len(n)
	if j := strings.IndexAny(n, "?#"); j >= 0 {
		end = j
	}
	head, tail := pctDecodeAll(n[:end]), n[end:]
	if k := strings.Index(head, "://"); k < 0 || strings.Count(head[k+3:], "/") > 0 {
		head = strings.TrimRight(head, "/")
	}
	return head + pctDecodeAll(tail)
}

func isScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if i == 0 && !alpha || !alpha && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// pctNorm upper-cases percent-encodings and decodes those of unreserved characters (§6.2.2.1, §6.2.2.2).
func pctNorm(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				if c := h<<4 | l; isUnreserved(c) {
					b.WriteByte(c)
				} else {
					b.WriteString("%" + strings.ToUpper(s[i+1:i+3]))
				}
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func pctDecodeAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(h<<4 | l)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// removeDots is RFC 3986 §5.2.4.
func removeDots(in string) string {
	var out []string
	abs := strings.HasPrefix(in, "/")
	segs := strings.Split(in, "/")
	if abs {
		segs = segs[1:]
	}
	for i, s := range segs {
		last := i == len(segs)-1
		switch s {
		case ".":
			if last {
				out = append(out, "")
			}
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, s)
		}
	}
	r := strings.Join(out, "/")
	if abs {
		return "/" + r
	}
	return r
}
