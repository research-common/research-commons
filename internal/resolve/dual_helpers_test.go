package resolve

import (
	"os"

	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// dualEnv reruns the resolver suite under the candidate dual-major reader: with RC_TEST_DUAL_READER=1 every
// store the shared test helpers build (world.store, world.resolve, storeOf) reads lines with wire.DualReader
// instead of wire.Read. On a corpus with no rc/2 line every answer must be the same (C-id-01); the tests that
// sign another major on purpose to check unsupported-input handling sign rc/3 instead (otherMajorRC), which the
// dual reader does not implement either.
const dualEnv = "RC_TEST_DUAL_READER"

func dualByEnv() bool { return os.Getenv(dualEnv) == "1" }

// newTestStore is the store every shared helper builds: the default one, or the dual-major one under dualEnv.
func newTestStore() *keylog.Store {
	if dualByEnv() {
		return dualStore()
	}
	return keylog.NewStore()
}

// dualStore is a store that reads with the candidate dual-major reader.
func dualStore() *keylog.Store { return keylog.NewStore(keylog.WithReader(wire.NewDualReader())) }

// otherMajorRC is the rc value of a major the reader under test does not implement: rc/2 for the unchanged
// reader (as the unsupported-input tests were written), rc/3 under the dual reader, which reads rc/2.
func otherMajorRC() string {
	if dualByEnv() {
		return "rc/3"
	}
	return "rc/2"
}
