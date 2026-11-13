package resolve

import (
	"strings"
	"testing"
)

// TestParseLicence: the SPDX license-expression grammar (SPDX 3.0.1 Annex B; 2.3 Annex D), syntax only. Valid:
// ids, `+`, WITH, AND/OR in either all-upper or all-lower case, parentheses, LicenseRef- and DocumentRef-…:LicenseRef-….
// Unparsable: every way the grammar's rules are broken. Each row carries the references it must name.
func TestParseLicence(t *testing.T) {
	ok := map[string][]string{
		"CC-BY-4.0":   nil,
		"MIT":         nil,
		"Apache-2.0+": nil,
		"GPL-2.0-or-later WITH Bison-exception-2.2": nil,
		"LGPL-2.1-only OR MIT OR BSD-3-Clause":      nil,
		"MIT and Apache-2.0":                        nil,
		"mit":                                       nil, // ids match case-insensitively; written as given
		"(MIT OR Apache-2.0) AND CC0-1.0":           nil,
		"(MIT)":                                     nil,
		"((MIT))":                                   nil,
		"(MIT)AND(Apache-2.0)":                      nil,
		"LicenseRef-X AND CC-BY-4.0":                {"LicenseRef-X"},
		"LicenseRef-MIT-Style-1":                    {"LicenseRef-MIT-Style-1"},
		"DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2": {"DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2"},
		"GPL-2.0-only WITH AdditionRef-x":                  nil,
		"LicenseRef-A OR LicenseRef-B OR LicenseRef-A":     {"LicenseRef-A", "LicenseRef-B"},
		"Some-Unlisted-Id-9.9":                             nil, // syntactically valid, not on any list this tool holds
	}
	for expr, want := range ok {
		got, err := ParseLicence(expr)
		if err != nil || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%q: refs %v err %v, want refs %v", expr, got, err, want)
		}
	}
	bad := []string{
		"", " ", "not spdx", "MIT AND", "AND MIT", "MIT OR OR Apache-2.0", "(MIT", "MIT)", "()", "MIT Apache-2.0",
		"MIT And Apache-2.0", "MIT WITH", "MIT WITH LicenseRef-X", "MIT WITH Apache-2.0+", "MIT +", "+MIT", "MIT+ +",
		"LicenseRef-X+", "licenseref-x", "LicenseRef-", "LicenseRef-a_b", "DocumentRef-d", "DocumentRef-:LicenseRef-x",
		"DocumentRef-d:Other-x", "MIT; DROP", "MIT,Apache-2.0", "MIT/Apache-2.0", "MIT\nAND Apache-2.0", "CC BY 4.0",
		"GPL-2.0-only WITHBison", "MITAND Apache-2.0", "MIT ANDApache-2.0", "MIT WITH WITH x", "<script>", "\x1b[31mMIT",
		strings.Repeat("(", MaxLicenceDepth+1) + "MIT" + strings.Repeat(")", MaxLicenceDepth+1),
		strings.Repeat("MIT OR ", MaxLicenceBytes) + "MIT",
	}
	for _, expr := range bad {
		if refs, err := ParseLicence(expr); err == nil {
			t.Errorf("%q parsed (refs %v)", expr, refs)
		}
	}
	// the nesting bound is exact: MaxLicenceDepth levels parse
	if _, err := ParseLicence(strings.Repeat("(", MaxLicenceDepth) + "MIT" + strings.Repeat(")", MaxLicenceDepth)); err != nil {
		t.Errorf("nesting at the bound: %v", err)
	}
}
