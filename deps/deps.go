// Package deps parses JavaScript dependency manifests into a normalized
// list of external references. It performs PARSING ONLY and never touches
// the network. The remote package decides whether to check anything.
//
// Supported inputs:
//   - package.json        (declared dependencies and version ranges)
//   - package-lock.json   (resolved versions, resolved URLs, integrity hashes)
//
// Note: these files are parsed as data. We do not run npm, we do not
// install anything, and we do not execute lifecycle scripts.
package deps

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Reference is one external dependency as declared or resolved.
type Reference struct {
	Name      string `json:"name"`
	Version   string `json:"version"`   // resolved version if known, else the range
	Range     string `json:"range"`     // declared semver range from package.json
	Resolved  string `json:"resolved"`  // resolved tarball URL from lockfile
	Integrity string `json:"integrity"` // integrity hash from lockfile
	Dev       bool   `json:"dev"`       // devDependency
	Source    string `json:"source"`    // "package.json" or "package-lock.json"
}

// Manifest is the normalized result of parsing one repo's dependency files.
type Manifest struct {
	References []Reference `json:"references"`
}

// packageJSON is the subset of package.json we care about.
type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Scripts              map[string]string `json:"scripts"`
}

// lockfileV2V3 covers npm lockfile v2/v3 ("packages" map).
type lockfileV2V3 struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version   string `json:"version"`
		Resolved  string `json:"resolved"`
		Integrity string `json:"integrity"`
		Dev       bool   `json:"dev"`
	} `json:"packages"`
	// v1 fallback
	Dependencies map[string]struct {
		Version   string `json:"version"`
		Resolved  string `json:"resolved"`
		Integrity string `json:"integrity"`
		Dev       bool   `json:"dev"`
	} `json:"dependencies"`
}

// LifecycleScripts is returned separately because install/postinstall
// scripts are a known malware execution vector worth surfacing.
type LifecycleScripts struct {
	Scripts map[string]string
}

// ParsePackageJSON parses package.json content. Returns the declared
// references and any lifecycle scripts (preinstall/install/postinstall etc).
func ParsePackageJSON(content []byte) ([]Reference, *LifecycleScripts, error) {
	var pj packageJSON
	if err := json.Unmarshal(content, &pj); err != nil {
		return nil, nil, fmt.Errorf("package.json parse: %w", err)
	}

	var refs []Reference
	add := func(m map[string]string, dev bool) {
		for name, rng := range m {
			refs = append(refs, Reference{
				Name:   name,
				Range:  rng,
				Dev:    dev,
				Source: "package.json",
			})
		}
	}
	add(pj.Dependencies, false)
	add(pj.DevDependencies, true)
	add(pj.OptionalDependencies, false)
	add(pj.PeerDependencies, false)

	var ls *LifecycleScripts
	if len(pj.Scripts) > 0 {
		interesting := map[string]bool{
			"preinstall": true, "install": true, "postinstall": true,
			"prepare": true, "prepublish": true, "prepublishOnly": true,
		}
		found := map[string]string{}
		for name, body := range pj.Scripts {
			if interesting[name] {
				found[name] = body
			}
		}
		if len(found) > 0 {
			ls = &LifecycleScripts{Scripts: found}
		}
	}

	return refs, ls, nil
}

// ParseLockfile parses package-lock.json (v1, v2, or v3). Returns the
// resolved references with their resolved URLs and integrity hashes.
func ParseLockfile(content []byte) ([]Reference, error) {
	var lf lockfileV2V3
	if err := json.Unmarshal(content, &lf); err != nil {
		return nil, fmt.Errorf("package-lock.json parse: %w", err)
	}

	var refs []Reference

	// v2/v3: "packages" keyed by path ("node_modules/foo")
	for path, p := range lf.Packages {
		if path == "" {
			continue // the root project entry
		}
		name := path
		if i := lastNodeModules(path); i >= 0 {
			name = path[i:]
		}
		refs = append(refs, Reference{
			Name:      name,
			Version:   p.Version,
			Resolved:  p.Resolved,
			Integrity: p.Integrity,
			Dev:       p.Dev,
			Source:    "package-lock.json",
		})
	}

	// v1 fallback: "dependencies" keyed by name
	if len(lf.Packages) == 0 {
		for name, p := range lf.Dependencies {
			refs = append(refs, Reference{
				Name:      name,
				Version:   p.Version,
				Resolved:  p.Resolved,
				Integrity: p.Integrity,
				Dev:       p.Dev,
				Source:    "package-lock.json",
			})
		}
	}

	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Name == refs[j].Name {
			return refs[i].Version < refs[j].Version
		}
		return refs[i].Name < refs[j].Name
	})
	return refs, nil
}

// lastNodeModules returns the index just after the final "node_modules/"
// segment, so "node_modules/a/node_modules/b" yields the index of "b".
func lastNodeModules(path string) int {
	const marker = "node_modules/"
	idx := -1
	for i := 0; i+len(marker) <= len(path); i++ {
		if path[i:i+len(marker)] == marker {
			idx = i + len(marker)
		}
	}
	return idx
}
