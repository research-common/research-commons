package rctime

import (
	"testing"
)

func TestParseUTCAccepts(t *testing.T) {
	for _, s := range []string{
		"2026-10-12T20:00:00Z", "2026-10-12T20:11:58.25Z", "2026-10-12T20:12:35.000000012Z",
		"2026-10-14T18:01:00.5Z", "2016-12-31T23:59:60Z", "2024-02-29T00:00:00Z", "0001-01-01T00:00:00Z",
		"2015-06-30T23:59:60.5Z", // leap second rule is position, not a table: any month end
	} {
		got, err := ParseUTC(s)
		if err != nil {
			t.Errorf("%s: %v", s, err)
			continue
		}
		if Format(got) != s {
			t.Errorf("Format(ParseUTC(%s)) = %s", s, Format(got))
		}
	}
}

func TestParseUTCRefuses(t *testing.T) {
	for _, s := range []string{
		"2026-10-12T20:11:58.250Z",        // N8 trailing zero
		"2026-10-12T20:12:35.0000000120Z", // N9 ten digits (also trailing zero)
		"2026-10-12T20:12:35.0000000121Z", // ten digits, no trailing zero
		"2026-10-12T20:12:00+00:00",       // N10 numeric offset
		"2026-10-12T20:12:00.0Z", "2026-10-12T20:12:00.Z",
		"2026-10-12t20:12:00Z", "2026-10-12T20:12:00z", "2026-10-12 20:12:00Z",
		"2026-10-12T20:12:00", // no Z where UTC is required
		"2026-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "2026-10-12T24:00:00Z", "2026-10-12T20:60:00Z",
		"2026-10-12T23:59:60Z", // not the last day of the month
		"2016-12-31T23:58:60Z", // not 23:59
		"2026-10-12T20:12:00-00:00", "26-10-12T20:12:00Z", "2026-10-12T20:12Z",
	} {
		if _, err := ParseUTC(s); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestParseIn(t *testing.T) {
	ok := []struct{ s, scale string }{
		{"2026-10-12T20:12:35.000000012", "TAI"}, // V9
		{"2026-10-12T20:12:35Z", "UTC"},
		{"2026-10-12T20:12:35Z", "UTC(NIST)"},
		{"2026-10-12T20:12:35Z", ""},
		{"2026-10-12T20:12:35", "TT(BIPM08)"},
	}
	for _, c := range ok {
		if _, err := ParseIn(c.s, c.scale); err != nil {
			t.Errorf("%s in %q: %v", c.s, c.scale, err)
		}
	}
	bad := []struct{ s, scale string }{
		{"2026-10-12T20:12:35.000000012Z", "TAI"}, // N13
		{"2016-12-31T23:59:60", "TAI"},            // N12
		{"2026-10-12T20:12:35", "UTC"},
		{"2026-10-12T20:12:35", ""},
	}
	for _, c := range bad {
		if _, err := ParseIn(c.s, c.scale); err == nil {
			t.Errorf("%s in %q accepted", c.s, c.scale)
		}
	}
}

func TestTimescales(t *testing.T) {
	for _, s := range []string{"TAI", "TT", "TDB", "TCG", "TCB", "UT1", "UTC", "GPS", "LOCAL", "TT(BIPM08)", "UTC(NIST)"} {
		if !ValidTimescale(s) {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{"TDT", "IAT", "ET", "GMT", "tai", "TT()", "TT(a(b))", "TT(x", ""} {
		if ValidTimescale(s) {
			t.Errorf("%s accepted", s)
		}
	}
}

// TestCompare: parsed order, never text order (§1.1).
func TestCompare(t *testing.T) {
	p := func(s string) Time {
		t.Helper()
		v, err := ParseUTC(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	order := []string{
		"2016-12-31T23:59:59Z", "2016-12-31T23:59:59.999999999Z", "2016-12-31T23:59:60Z",
		"2016-12-31T23:59:60.5Z", "2017-01-01T00:00:00Z", "2017-01-01T00:00:00.25Z", "2017-01-01T00:00:00.5Z",
	}
	for i := range order {
		for j := range order {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := Compare(p(order[i]), p(order[j])); got != want {
				t.Errorf("Compare(%s, %s) = %d", order[i], order[j], got)
			}
		}
	}
	// The case §1.1 names: "…00.5Z" sorts after "…00.25Z" though its string sorts before it.
	a, b := "2017-01-01T00:00:00.5Z", "2017-01-01T00:00:00.25Z"
	if a < b || Compare(p(a), p(b)) != 1 {
		t.Fatal("text order and parsed order should disagree here")
	}
}

func TestParseDate(t *testing.T) {
	for _, s := range []string{"2026-09-01", "2024-02-29"} {
		if _, err := ParseDate(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"2026-02-29", "2026-9-01", "2026-09-01Z", "2026-09-01T00:00:00Z", ""} {
		if _, err := ParseDate(s); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

// FuzzTime: every accepted value has exactly one spelling, and Compare is consistent with it.
func FuzzTime(f *testing.F) {
	for _, s := range []string{"2026-10-12T20:00:00Z", "2016-12-31T23:59:60.5Z", "2026-10-12T20:11:58.250Z", "2026-10-12T20:12:35.000000012"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := parse(s)
		if err != nil {
			return
		}
		if Format(v) != s {
			t.Fatalf("%q accepted but its canonical spelling is %q", s, Format(v))
		}
		if Compare(v, v) != 0 {
			t.Fatal("not reflexive")
		}
	})
}
