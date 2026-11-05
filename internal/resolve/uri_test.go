package resolve

import "testing"

// TestCompareSource: completeness compares URI sources after RFC 3986 §6.2.2 normalization, so a different
// spelling of one URI stays in scope; spellings equal only once a trailing slash or a percent-encoding is set
// aside are undecided (never out of scope, which would let a missing reading read `ok`); anything else differs.
func TestCompareSource(t *testing.T) {
	const e = "https://data.example.org/bmrs/api/v1/datasets/B1610"
	for _, c := range []struct {
		a, b string
		want uriMatch
	}{
		{e, e, uriEqual},
		{e, "HTTPS://Data.Example.ORG/bmrs/api/v1/datasets/B1610", uriEqual},     // scheme and host case
		{e, "https://data.example.org:443/bmrs/api/v1/datasets/B1610", uriEqual}, // default port
		{e, "https://data.example.org/bmrs/api/./v1/x/../datasets/B1610", uriEqual},
		{e, "https://data.example.org/bmrs/api/v1/datasets/%42%31610", uriEqual}, // unreserved decoded
		{"https://e.example/a%2fb", "https://e.example/a%2Fb", uriEqual},         // percent-encoding case
		{"https://e.example", "https://e.example/", uriEqual},                    // empty path is "/"
		{e, e + "/", uriLoose}, // trailing slash: another path
		{e, "https://data.example.org/bmrs/api/v1/datasets%2FB1610", uriLoose}, // %2F is not "/"
		{e, "https://data.example.org:8443/bmrs/api/v1/datasets/B1610", uriDiffer},
		{e, "http://data.example.org/bmrs/api/v1/datasets/B1610", uriDiffer},
		{e, "https://data.example.org/bmrs/api/v1/datasets/B1620", uriDiffer},
		{e, "https://data.example.org/bmrs/api/v1/datasets/b1610", uriDiffer}, // path case is significant
		{e + "?q=1", e + "?q=2", uriDiffer},
		{"urn:example:station-7", "URN:example:station-7", uriEqual},
		{"urn:example:station-7", "urn:example:station-8", uriDiffer},
		{"station 7", "Station 7", uriDiffer}, // not a URI: compared as text
		{"https://[2001:db8::1]:443/x", "https://[2001:DB8::1]/x", uriEqual},
	} {
		if got := compareSource(c.a, c.b); got != c.want {
			t.Errorf("compareSource(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := compareSource(c.b, c.a); got != c.want {
			t.Errorf("not symmetric: compareSource(%q, %q) = %d, want %d", c.b, c.a, got, c.want)
		}
	}
}
