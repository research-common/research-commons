package reqlog

import (
	"errors"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

const d1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func line(s string) []byte { return []byte(s + "\n") }

const good = `{"endpoint":"https://api.example/v1/s","parameters":{"period":"2026-09"},"response_digest":"` + d1 + `","status":200,"time":"2026-10-16T05:00:00Z"}`

func TestParseRoundTrip(t *testing.T) {
	es, err := Parse(line(good))
	if err != nil || len(es) != 1 || es[0].Status != 200 || es[0].ResponseDigest != d1 {
		t.Fatalf("%v %+v", err, es)
	}
	if got := string(Encode(es)); got != good+"\n" {
		t.Fatalf("encode: %s", got)
	}
	// an x_ extension is kept and ignored; members in any order, whitespace allowed
	ext := `{ "x_retry": 2, "time":"2026-10-16T05:00:00Z","status":404,"response_digest":"` + d1 + `","parameters":{},"endpoint":"e"}`
	if es, err := Parse(line(ext)); err != nil || es[0].Status != 404 {
		t.Fatalf("ext: %v", err)
	}
	if SharedEndpoint(append(es, Entry{Endpoint: "other"})) != "" || SharedEndpoint(es) != "https://api.example/v1/s" {
		t.Fatal("shared endpoint")
	}
}

func TestParseRefuses(t *testing.T) {
	mut := func(from, to string) []byte { return line(strings.Replace(good, from, to, 1)) }
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"empty":             {nil, "empty"},
		"no final newline":  {[]byte(good), "line feed"},
		"blank line":        {append(line(good), '\n'), "line 2: blank line"},
		"crlf":              {[]byte(good + "\r\n"), "carriage return"},
		"not an object":     {line(`[1]`), "not an object"},
		"undefined member":  {mut(`"status"`, `"method":"GET","status"`), `undefined member "method"`},
		"missing status":    {mut(`,"status":200`, ``), "missing status"},
		"status range":      {mut(`200`, `1000`), "status"},
		"status type":       {mut(`200`, `"200"`), "status"},
		"empty endpoint":    {mut(`https://api.example/v1/s`, ``), "endpoint"},
		"parameters type":   {mut(`{"period":"2026-09"}`, `[]`), "parameters"},
		"time offset":       {mut(`05:00:00Z`, `05:00:00+01:00`), "time"},
		"digest uppercase":  {mut(`sha256:1111`, `sha256:AAAA`), "response_digest"},
		"duplicate member":  {mut(`"status":200`, `"status":200,"status":201`), "duplicate"},
		"float":             {mut(`200`, `200.0`), "line 1"},
		"second line wrong": {append(line(good), line(`{}`)...), "line 2: missing"},
	} {
		_, err := Parse(c.b)
		var m *Malformed
		if !errors.As(err, &m) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestParseLimits(t *testing.T) {
	long := line(strings.Replace(good, `"period":"2026-09"`, `"p":"`+strings.Repeat("a", MaxLineBytes)+`"`, 1))
	var l *Limit
	if _, err := Parse(long); !errors.As(err, &l) || !strings.Contains(l.Name, "request_log_line_bytes") {
		t.Fatalf("line: %v", err)
	}
	// control: just under the line limit reads
	pad := MaxLineBytes - len(good) - 2
	ok := line(strings.Replace(good, `"period":"2026-09"`, `"p":"`+strings.Repeat("a", pad)+`"`, 1))
	if _, err := Parse(ok); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, err := Parse(make([]byte, MaxBytes+1)); !errors.As(err, &l) || !strings.Contains(l.Name, "request_log_bytes") {
		t.Fatalf("bytes: %v", err)
	}
	_ = canon.MaxDepth
}
