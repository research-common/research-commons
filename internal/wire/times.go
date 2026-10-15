package wire

import (
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/rctime"
	"github.com/research-common/research-commons/internal/refusal"
)

// checkBodyTimes applies §1.1 to every body field the kind table (§5) types as ts or date. It checks the
// fields that are present; whether a required field is missing is the kind schema's job, not this one's.
//
// UTC fields: capture.at, finality.state_at_capture.captured_at, effective, and window bounds outside a
// referent (sampling.window). Referent fields (referent.at, referent.window.from/to) are in the referent's
// timescale, UTC when it names none. frozen_before.date is a full-date.
func checkBodyTimes(kind string, body *canon.Object) error {
	switch kind {
	case "observed":
		if err := utcAt(body, "capture", "at"); err != nil {
			return err
		}
		if err := utcAt(body, "finality", "state_at_capture", "captured_at"); err != nil {
			return err
		}
		if ref, ok := obj(body, "referent"); ok {
			scale := ""
			if v, ok := ref.Get("timescale"); ok {
				s, ok := v.(canon.String)
				if !ok || !rctime.ValidTimescale(string(s)) {
					return refusal.Malformed("referent timescale is not an admitted FITS code")
				}
				scale = string(s)
			}
			for _, path := range [][]string{{"at"}, {"window", "from"}, {"window", "to"}} {
				if s, ok, err := strAt(ref, path...); err != nil {
					return err
				} else if ok {
					if _, err := rctime.ParseIn(s, scale); err != nil {
						return err
					}
				}
			}
		}
		return samplingWindow(body)
	case "authored":
		return samplingWindow(body)
	case "rotate_key", "revoke_key":
		return utcAt(body, "effective")
	case "edition":
		if s, ok, err := strAt(body, "contents", "frozen_before", "date"); err != nil {
			return err
		} else if ok {
			if _, err := rctime.ParseDate(s); err != nil {
				return err
			}
		}
	}
	return nil
}

func samplingWindow(body *canon.Object) error {
	if err := utcAt(body, "sampling", "window", "from"); err != nil {
		return err
	}
	return utcAt(body, "sampling", "window", "to")
}

func utcAt(o *canon.Object, path ...string) error {
	s, ok, err := strAt(o, path...)
	if err != nil || !ok {
		return err
	}
	_, err = rctime.ParseUTC(s)
	return err
}

func obj(o *canon.Object, k string) (*canon.Object, bool) {
	v, ok := o.Get(k)
	if !ok {
		return nil, false
	}
	c, ok := v.(*canon.Object)
	return c, ok
}

// strAt follows path through nested objects. A missing step is "not present"; a present leaf that is not a
// string is malformed, because every field this walks is typed ts or date.
func strAt(o *canon.Object, path ...string) (string, bool, error) {
	for _, k := range path[:len(path)-1] {
		var ok bool
		if o, ok = obj(o, k); !ok {
			return "", false, nil
		}
	}
	v, ok := o.Get(path[len(path)-1])
	if !ok {
		return "", false, nil
	}
	s, ok := v.(canon.String)
	if !ok {
		return "", false, refusal.Malformed("%v is not a time string", path)
	}
	return string(s), true, nil
}
