package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// TestIdentityCompromisedHostDrill is the compromised-operational-host custody drill (identity profile §8,
// "Compromised-host drill, recorded"), run through the command line only, both algorithms. The root key R never
// touches the operational host: every root act is prepared on a store (--prepare), checked and signed with key sign
// on a machine with no store, and completed (--complete). The operational host holds the store, the worker key K
// and the hub checkout (here: a hub store it publishes to with pull).
//
//  1. setup: inception I and grant G of I to K prepared on the operational store, signed off-host, completed; two
//     acts a1, a2 for I under G; the hub takes them;
//  2. compromise: the attacker copies the whole host (store and K's key file); R's file is nowhere in the copy;
//  3. (a) the attacker publishes two acts for I under G with K, forking K's log after a2;
//  4. (b) the attacker prepares a grant of I to its own key and presents the package as a routine grant to K: the
//     holder, who prepared that routine grant on a clean store from the hub and took the sha256 of its PAE, runs
//     key sign --expect-pae-sha256 with that digest: refused, no signature written; package show names the
//     attacker's key as the delegate; every store byte-identical;
//  5. (c) the attacker cannot sign as the root: identity grant/cut with any key it holds is refused, nothing written;
//  6. recovery on a clean machine with a fresh store pulled from the hub (never from the compromised store; the
//     attacker's acts are not in it): identity cut G with --last-good a2 (the last act the holder can attest),
//     reason key_compromise, prepared there, signed off-host after the digest check, completed; the cut's PAE is the
//     same when prepared on a store that also holds the attacker's acts (the cut does not depend on them);
//  7. a new worker key K2 on the clean machine, a grant G2 of I to K2 through the package, an act under G2;
//  8. a reader pulls everything, the attacker's store included: a1 and a2 count; the attacker's acts are denied,
//     cut_excluded; the act under G2 is eligible and counted; the forged grant exists nowhere.
//
// What it does not cover: exclusion by origin inside the vouched prefix (an attacker act that is an ancestor of
// --last-good keeps counting, §8), and a compromised root key (a new identity, not a recovery).
func TestIdentityCompromisedHostDrill(t *testing.T) {
	conformance.Covers(t, "C-id-40") // with the simple-path, package and connector tests and the manual Nano X drill (§8)
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			ts := []string{"--ts", "2026-11-16T00:00:00Z"}
			root := newExtHome(t, alg)     // root.store is the operational store; root.keyF lives off the host
			holder := newSigningMachine(t) // the root holder's signing machine: no store
			// offSign: the holder checks the package's PAE digest against one computed on a clean machine, then signs.
			offSign := func(pkgPath, want string) string {
				t.Helper()
				out := filepath.Join(holder.dir, filepath.Base(pkgPath)+".sig")
				r := holder.run("key", "sign", "--package", pkgPath, "--key", root.keyF, "--expect-pae-sha256", want, "--out", out, "--json")
				if r.code != ExitOK {
					t.Fatalf("key sign %s: %d %s%s", pkgPath, r.code, r.stdout, r.stderr)
				}
				return out
			}
			paeSum := func(pkg *canon.Object) string {
				s := sha256.Sum256(paeOf(t, pkg))
				return hex.EncodeToString(s[:])
			}
			hub := &idHome{t: t, store: drillStore(t)}

			// 1. setup on the operational host
			np, npkg := root.prepare("new.pkg", append([]string{"identity", "new"}, ts...)...)
			r := root.complete([]string{"identity", "new"}, np, offSign(np, paeSum(npkg)))
			if r.code != ExitOK {
				t.Fatalf("inception: %d %s", r.code, r.stdout)
			}
			ident := string(jsonOf(t, r).Members["identity"].(canon.String))
			opDir := t.TempDir()
			kf, ks := newKeyFile(t, opDir, alg)
			worker := &idHome{t: t, store: root.store, key: kf, signer: ks}
			d := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c0", "worker first line"), "--licence", "CC0-1.0"))
			grantCmd := append([]string{"identity", "grant", "--identity", ident, "--delegate", ks, "--delegate-inception", d, "--permissions", anyContentPerm}, ts...)
			gp, gpkg := root.prepare("grant.pkg", grantCmd...)
			if r = root.complete([]string{"identity", "grant"}, gp, offSign(gp, paeSum(gpkg))); r.code != ExitOK {
				t.Fatalf("grant: %d %s", r.code, r.stdout)
			}
			grant := string(jsonOf(t, r).Members["grant"].(canon.String))
			a1 := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("a1", "legit one"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant))
			a2 := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("a2", "legit two"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant))
			hub.pullFrom(worker)

			// 2. compromise: a full copy of the operational host
			atkDir := t.TempDir()
			atkStore := filepath.Join(atkDir, "store")
			copyTree(t, root.store, atkStore)
			kb, _ := os.ReadFile(kf)
			atkK := filepath.Join(atkDir, "worker.key")
			os.WriteFile(atkK, kb, 0o600)
			os.Chmod(atkK, 0o600)
			rb, _ := os.ReadFile(root.keyF)
			filepath.WalkDir(atkDir, func(p string, de fs.DirEntry, err error) error {
				if err == nil && !de.IsDir() {
					if b, _ := os.ReadFile(p); bytes.Contains(b, bytes.TrimSpace(rb)) {
						t.Fatalf("the root key file is on the operational host: %s", p)
					}
				}
				return nil
			})
			thief := &idHome{t: t, store: atkStore, key: atkK, signer: ks}

			// 3. (a) acts as I under G with K, forking K's log after a2
			t1 := firstID(t, thief.ok("publish", "--kind", "authored", "--content", thief.file("t1", "forged one"), "--licence", "CC0-1.0",
				"--as", ident, "--grant", grant, "--prev", a2))
			t2 := firstID(t, thief.ok("publish", "--kind", "authored", "--content", thief.file("t2", "forged two"), "--licence", "CC0-1.0",
				"--as", ident, "--grant", grant, "--prev", t1))
			for _, id := range []string{t1, t2} {
				if member(jsonOf(t, thief.read("show", id)), "actor", "state") != canon.String("eligible") {
					t.Fatalf("before the cut the forged act %s should read eligible (that is the damage)", id[:12])
				}
			}

			// 4. (b) a forged grant package presented as routine
			akf, aks := newKeyFile(t, t.TempDir(), alg)
			atk := &idHome{t: t, store: atkStore, key: akf, signer: aks}
			da := firstID(t, atk.ok("publish", "--kind", "authored", "--content", atk.file("da", "attacker first line"), "--licence", "CC0-1.0"))
			amendPerm := `[{"kind":"authored","targets":{"any_content":true},"amend":true}]`
			forgedPath := filepath.Join(atkDir, "routine-grant.pkg")
			if r := runIn(atkStore, nil, append([]string{"identity", "grant", "--identity", ident, "--delegate", aks, "--delegate-inception", da,
				"--permissions", amendPerm}, append(ts, "--prepare", forgedPath, "--signer", root.signer, "--json")...)...); r.code != ExitOK {
				t.Fatalf("attacker prepare: %d %s", r.code, r.stdout)
			}
			forged := readPkg(t, forgedPath)
			// the holder's own copy of the routine grant, prepared on a clean store pulled from the hub
			check := newExtHome(t, alg)
			check.pullFrom(hub.store)
			check.signer = root.signer
			_, routine := check.prepare("routine.pkg", append([]string{"identity", "grant", "--identity", ident, "--delegate", ks,
				"--delegate-inception", d, "--permissions", amendPerm}, ts...)...)
			want := paeSum(routine)
			snap := map[string]string{"op": storeBytes(t, root.store), "atk": storeBytes(t, atkStore), "hub": storeBytes(t, hub.store), "check": storeBytes(t, check.store)}
			sigOut := filepath.Join(holder.dir, "forged.sig")
			if r := holder.run("key", "sign", "--package", forgedPath, "--key", root.keyF, "--expect-pae-sha256", want, "--out", sigOut, "--json"); r.code != ExitWrong {
				t.Fatalf("key sign of the forged package with the holder's digest: %d %s", r.code, r.stdout)
			}
			if _, err := os.Stat(sigOut); err == nil {
				t.Fatal("key sign wrote a signature for the forged package")
			}
			if r := holder.run("package", "show", forgedPath, "--json"); r.code != ExitOK || !strings.Contains(r.stdout, aks) || strings.Contains(r.stdout, ks) {
				t.Fatalf("package show does not name the real delegate: %d %s", r.code, r.stdout)
			}
			// 5. (c) no root signature without R
			for _, k := range []string{atkK, akf} {
				for _, args := range [][]string{
					{"identity", "grant", "--identity", ident, "--delegate", aks, "--delegate-inception", da, "--permissions", amendPerm},
					{"identity", "cut", "--identity", ident, "--grant", grant, "--last-good", t2, "--reason", "superseded"},
				} {
					if r := runIn(atkStore, nil, append(args, "--key", k, "--json")...); r.code == ExitOK {
						t.Fatalf("a root act signed without the root key: %v %s", args[:2], r.stdout)
					}
				}
			}
			for name, s := range map[string]string{"op": root.store, "atk": atkStore, "hub": hub.store, "check": check.store} {
				if storeBytes(t, s) != snap[name] {
					t.Fatalf("a refused step wrote to the %s store", name)
				}
			}

			// 6. recovery on a clean machine, fresh store from the hub
			clean := newExtHome(t, alg)
			clean.signer = root.signer
			clean.pullFrom(hub.store)
			for _, id := range []string{t1, t2, da} {
				if lineOf(t, clean.store, id) != "" {
					t.Fatalf("the recovery store holds a line written on the compromised host: %s", id[:12])
				}
			}
			cutCmd := append([]string{"identity", "cut", "--identity", ident, "--grant", grant, "--last-good", a2, "--reason", "key_compromise"}, ts...)
			cp, cpkg := clean.prepare("cut.pkg", cutCmd...)
			tainted := newExtHome(t, alg)
			tainted.signer = root.signer
			tainted.pullFrom(hub.store)
			tainted.pullFrom(atkStore)
			if _, tp := tainted.prepare("cut.pkg", cutCmd...); paeSum(tp) != paeSum(cpkg) {
				t.Fatal("the cut's PAE depends on the attacker's lines")
			}
			r = clean.complete([]string{"identity", "cut"}, cp, offSign(cp, paeSum(cpkg)))
			if r.code != ExitOK {
				t.Fatalf("cut: %d %s", r.code, r.stdout)
			}
			// 7. new worker key and grant on the clean machine
			k2f, k2s := newKeyFile(t, t.TempDir(), alg)
			w2 := &idHome{t: t, store: clean.store, key: k2f, signer: k2s}
			d2 := firstID(t, w2.ok("publish", "--kind", "authored", "--content", w2.file("d2", "new worker first line"), "--licence", "CC0-1.0"))
			g2p, g2pkg := clean.prepare("grant2.pkg", append([]string{"identity", "grant", "--identity", ident, "--delegate", k2s,
				"--delegate-inception", d2, "--permissions", anyContentPerm}, ts...)...)
			if r = clean.complete([]string{"identity", "grant"}, g2p, offSign(g2p, paeSum(g2pkg))); r.code != ExitOK {
				t.Fatalf("grant G2: %d %s", r.code, r.stdout)
			}
			g2 := string(jsonOf(t, r).Members["grant"].(canon.String))
			b1 := firstID(t, w2.ok("publish", "--kind", "authored", "--content", w2.file("b1", "after recovery"), "--licence", "CC0-1.0", "--as", ident, "--grant", g2))

			// 8. a reader pulls everything
			reader := &idHome{t: t, store: drillStore(t)}
			for _, s := range []string{hub.store, atkStore, root.store, clean.store} {
				if r := reader.read("pull", s); r.code != ExitOK {
					t.Fatalf("reader pull: %s", r.stdout)
				}
			}
			for _, id := range []string{a1, a2, b1} {
				if sh := jsonOf(t, reader.read("show", id)); member(sh, "actor", "state") != canon.String("eligible") || sh.Members["counted"] != canon.String("counted") {
					t.Fatalf("legitimate act %s: %s", id[:12], canon.Encode(sh))
				}
			}
			for _, id := range []string{t1, t2} {
				sh := jsonOf(t, reader.read("show", id))
				if member(sh, "actor", "state") != canon.String("denied") || sh.Members["counted"] != canon.String("not counted") ||
					!strings.Contains(string(canon.Encode(member(sh, "actor", "reasons"))), "cut_excluded") {
					t.Fatalf("forged act %s: %s", id[:12], canon.Encode(sh))
				}
			}
			fid := string(forged.Members["statement"].(canon.String))
			for _, s := range []string{reader.store, atkStore, clean.store, hub.store} {
				if lineOf(t, s, fid) != "" {
					t.Fatal("the forged grant was committed somewhere")
				}
			}
		})
	}
}
