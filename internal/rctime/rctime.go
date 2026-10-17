// Package rctime parses and compares the time values of wire-format note §1.1.
//
// A time value is an RFC 3339 date-time in one canonical spelling: upper-case T, at most nine fractional
// digits with no trailing zeros (XML Schema 1.1 dateTimeCanonicalMap), and the offset Z only. A measurement
// recorded in a timescale other than UTC carries no offset at all, because Z asserts UTC. Second 60 is
// admitted only at 23:59:60 on the last day of a month, in UTC, as written; it is never normalised.
//
// Times are compared parsed, never as text. The string is kept so nothing finer than the parse is lost.
package rctime

import (
	"fmt"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/refusal"
)

// Time is one parsed time value.
type Time struct {
	// Sec is the calendar second as seconds since 1970-01-01T00:00:00 in the value's own scale, ignoring leap
	// seconds. A leap second carries the Sec of 23:59:59 and Leap set, so it sorts after every instant in
	// :59 and before the next minute.
	Sec   int64
	Leap  bool
	Nanos int32
	// UTC is true when the value carries Z.
	UTC bool
	// Text is the value exactly as written.
	Text string
}

// Compare orders two times in the same scale: -1, 0 or +1. The caller checks that the scales agree.
func Compare(a, b Time) int {
	switch {
	case a.Sec != b.Sec:
		return cmp(a.Sec < b.Sec)
	case a.Leap != b.Leap:
		return cmp(!a.Leap)
	case a.Nanos != b.Nanos:
		return cmp(a.Nanos < b.Nanos)
	}
	return 0
}

func cmp(less bool) int {
	if less {
		return -1
	}
	return 1
}

// ParseUTC parses a value that must be UTC (the envelope ts, capture.at).
func ParseUTC(s string) (Time, error) {
	t, err := parse(s)
	if err != nil {
		return t, err
	}
	if !t.UTC {
		return t, malformed(s, "missing Z")
	}
	return t, nil
}

// ParseIn parses a measurement time recorded in timescale ts ("" means UTC). In UTC or a UTC realisation the
// value carries Z; in any other scale it carries no offset and second 60 is refused.
func ParseIn(s, timescale string) (Time, error) {
	if timescale == "" || IsUTCScale(timescale) {
		return ParseUTC(s)
	}
	t, err := parse(s)
	if err != nil {
		return t, err
	}
	if t.UTC {
		return t, malformed(s, "Z asserts UTC; the referent names "+timescale)
	}
	if t.Leap {
		return t, malformed(s, "second 60 outside UTC")
	}
	return t, nil
}

// ParseDate parses an RFC 3339 full-date (fields typed `date`, e.g. frozen_before).
func ParseDate(s string) (time.Time, error) {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' || !digits(s[:4]) || !digits(s[5:7]) || !digits(s[8:]) {
		return time.Time{}, malformed(s, "not a full-date")
	}
	y, m, d := atoi(s[:4]), atoi(s[5:7]), atoi(s[8:])
	if m < 1 || m > 12 || d < 1 || d > daysIn(y, m) {
		return time.Time{}, malformed(s, "no such date")
	}
	return time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC), nil
}

var scales = map[string]bool{"TAI": true, "TT": true, "TDB": true, "TCG": true, "TCB": true, "UT1": true,
	"UTC": true, "GPS": true, "LOCAL": true}

// ValidTimescale reports whether s is an admitted FITS 4.0 Table 30 code, optionally followed by a
// realisation in parentheses (TT(BIPM08), UTC(NIST)). Deprecated codes (TDT, IAT, ET, GMT) are not admitted.
func ValidTimescale(s string) bool {
	code, real, has := strings.Cut(s, "(")
	if has && (len(real) < 2 || !strings.HasSuffix(real, ")") || strings.ContainsAny(real[:len(real)-1], "()")) {
		return false
	}
	return scales[code]
}

// IsUTCScale reports whether s is UTC or a UTC realisation.
func IsUTCScale(s string) bool {
	return s == "UTC" || strings.HasPrefix(s, "UTC(")
}

func malformed(s, why string) error {
	return refusal.Malformed("non-canonical time %q: %s", s, why)
}

// parse reads YYYY-MM-DDTHH:MM:SS[.f{1,9}][Z].
func parse(s string) (Time, error) {
	t := Time{Text: s}
	if len(s) < 19 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' {
		return t, malformed(s, "not an RFC 3339 date-time")
	}
	for _, f := range []string{s[:4], s[5:7], s[8:10], s[11:13], s[14:16], s[17:19]} {
		if !digits(f) {
			return t, malformed(s, "not an RFC 3339 date-time")
		}
	}
	y, mo, d := atoi(s[:4]), atoi(s[5:7]), atoi(s[8:10])
	h, mi, se := atoi(s[11:13]), atoi(s[14:16]), atoi(s[17:19])
	rest := s[19:]
	if strings.HasPrefix(rest, ".") {
		n := 1
		for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
			n++
		}
		frac := rest[1:n]
		switch {
		case len(frac) == 0:
			return t, malformed(s, "empty fraction")
		case len(frac) > 9:
			return t, malformed(s, "more than nine fractional digits")
		case frac[len(frac)-1] == '0':
			return t, malformed(s, "trailing zero in fraction")
		}
		ns := atoi(frac + strings.Repeat("0", 9-len(frac)))
		t.Nanos = int32(ns)
		rest = rest[n:]
	}
	switch rest {
	case "Z":
		t.UTC = true
	case "":
	default:
		return t, malformed(s, "offset other than Z")
	}
	if mo < 1 || mo > 12 || d < 1 || d > daysIn(y, mo) || h > 23 || mi > 59 || se > 60 {
		return t, malformed(s, "no such date or time")
	}
	if se == 60 {
		if h != 23 || mi != 59 || d != daysIn(y, mo) {
			return t, malformed(s, "second 60 outside 23:59 on the last day of a month")
		}
		t.Leap = true
		se = 59
	}
	t.Sec = time.Date(y, time.Month(mo), d, h, mi, se, 0, time.UTC).Unix()
	return t, nil
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func daysIn(y, m int) int {
	return time.Date(y, time.Month(m)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// Format writes t in the canonical spelling. Format(Parse(s)) == s for every s Parse accepts.
func Format(t Time) string {
	sec := t.Sec
	tt := time.Unix(sec, 0).UTC()
	s := tt.Format("2006-01-02T15:04:05")
	if t.Leap {
		s = s[:17] + "60"
	}
	if t.Nanos != 0 {
		f := strings.TrimRight(fmt.Sprintf("%09d", t.Nanos), "0")
		s += "." + f
	}
	if t.UTC {
		s += "Z"
	}
	return s
}
