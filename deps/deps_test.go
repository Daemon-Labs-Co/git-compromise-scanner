package deps

import (
	"sort"
	"testing"
)

func TestParsePackageJSON(t *testing.T) {
	content := []byte(`{
		"dependencies":         {"left-pad": "^1.0.0"},
		"devDependencies":      {"jest": "^29.0.0"},
		"optionalDependencies": {"fsevents": "^2.0.0"},
		"peerDependencies":     {"react": ">=17"},
		"scripts": {
			"test": "jest",
			"postinstall": "node setup.js"
		}
	}`)

	refs, ls, err := ParsePackageJSON(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 4 {
		t.Fatalf("got %d refs, want 4: %+v", len(refs), refs)
	}

	byName := map[string]Reference{}
	for _, r := range refs {
		byName[r.Name] = r
	}
	if r := byName["left-pad"]; r.Range != "^1.0.0" || r.Dev || r.Source != "package.json" {
		t.Errorf("left-pad = %+v", r)
	}
	if r := byName["jest"]; !r.Dev {
		t.Errorf("jest should be marked dev: %+v", r)
	}

	if ls == nil {
		t.Fatal("expected lifecycle scripts, got nil")
	}
	if ls.Scripts["postinstall"] != "node setup.js" {
		t.Errorf("lifecycle scripts = %+v", ls.Scripts)
	}
	if _, ok := ls.Scripts["test"]; ok {
		t.Error("'test' is not an install-time script and should not be surfaced")
	}
}

func TestParsePackageJSONNoLifecycle(t *testing.T) {
	refs, ls, err := ParsePackageJSON([]byte(`{"scripts": {"test": "jest"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Errorf("got %d refs, want 0", len(refs))
	}
	if ls != nil {
		t.Errorf("expected nil LifecycleScripts, got %+v", ls)
	}
}

func TestParsePackageJSONInvalid(t *testing.T) {
	if _, _, err := ParsePackageJSON([]byte("not json")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseLockfileV3(t *testing.T) {
	content := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"version": "1.0.0"},
			"node_modules/left-pad": {
				"version": "1.3.0",
				"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
				"integrity": "sha512-abc"
			},
			"node_modules/a/node_modules/b": {
				"version": "2.0.0",
				"resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz",
				"integrity": "sha512-def",
				"dev": true
			}
		}
	}`)

	refs, err := ParseLockfile(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("got %d refs, want 2 (root entry must be skipped): %+v", len(refs), refs)
	}
	// Nested path must resolve to the innermost package name.
	if refs[0].Name != "b" || !refs[0].Dev {
		t.Errorf("refs[0] = %+v, want name 'b' and dev=true", refs[0])
	}
	if refs[1].Name != "left-pad" || refs[1].Integrity != "sha512-abc" {
		t.Errorf("refs[1] = %+v", refs[1])
	}
	if !sort.SliceIsSorted(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name }) {
		t.Error("refs are not sorted by name")
	}
}

func TestParseLockfileV1Fallback(t *testing.T) {
	content := []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"left-pad": {
				"version": "1.3.0",
				"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
				"integrity": "sha512-abc"
			}
		}
	}`)
	refs, err := ParseLockfile(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Name != "left-pad" || refs[0].Source != "package-lock.json" {
		t.Fatalf("refs = %+v", refs)
	}
}

func TestParseLockfileInvalid(t *testing.T) {
	if _, err := ParseLockfile([]byte("{")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLastNodeModules(t *testing.T) {
	cases := []struct {
		path string
		want string // expected name after slicing, "" means idx < 0
	}{
		{"node_modules/foo", "foo"},
		{"node_modules/a/node_modules/b", "b"},
		{"node_modules/@scope/pkg", "@scope/pkg"},
		{"plain/path", ""},
	}
	for _, c := range cases {
		idx := lastNodeModules(c.path)
		if c.want == "" {
			if idx >= 0 {
				t.Errorf("lastNodeModules(%q) = %d, want negative", c.path, idx)
			}
			continue
		}
		if idx < 0 || c.path[idx:] != c.want {
			t.Errorf("lastNodeModules(%q): got %q, want %q", c.path, c.path[max(idx, 0):], c.want)
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
