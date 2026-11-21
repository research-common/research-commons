package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/research-common/research-commons/internal/wire"
)

// SignerStatements returns the installed statements of one signer, read through wire.ReadStored, keyed by id: the
// signer's part of Statements, read from its own directory only, so a writer's per-key check does not read the
// whole store. A line whose operation is hidden (a record whose replay failed) is skipped, as Statements skips it.
func (s *Store) SignerStatements(signer string) (map[string]*wire.Statement, error) {
	dir := s.dir("statements", signerDir(signer))
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]*wire.Statement{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]*wire.Statement{}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		st, rerr := wire.ReadStored(b)
		if rerr != nil || st.ID != e.Name() || st.Signer != signer || s.hidden(st.ID) {
			continue
		}
		out[st.ID] = st
	}
	return out, nil
}
