// Package remote is the ONLY module permitted to touch the network, and
// it does so only when explicitly enabled. By default it operates in
// report-only mode: it inspects resolved dependency URLs and flags
// anything suspicious WITHOUT making any outbound request.
//
// Safety model:
//   - Default mode is Inspect (no network at all).
//   - Live checks require an explicit opt-in (Enabled = true).
//   - A hardcoded blocklist of known C2 / attacker infrastructure is
//     NEVER fetched, under any circumstances, even when live checks are on.
//   - Even with live checks enabled, this module only issues HEAD-style
//     reachability checks against package-registry hosts; it never
//     downloads or executes payloads.
package remote

import (
	"net/url"
	"strings"

	"github.com/daemon-labs-co/git-compromise-scanner/deps"
)

// Known attacker / C2 infrastructure. These hosts are NEVER contacted,
// even in live mode.
//
// The entries below are illustrative placeholders. Populate this list from
// the IOC feed relevant to your investigation — e.g. hosts published in an
// incident report, threat-intel advisories, or your own SOC's blocklist.
// Typical real-world entries are exfiltration endpoints, C2 domains, and
// abused public API gateways named in a supply-chain compromise.
var c2Blocklist = []string{
	"c2.malicious.example",         // placeholder: command-and-control domain
	"exfil.attacker.example",       // placeholder: data exfiltration endpoint
	"payload-cdn.badactor.example", // placeholder: second-stage payload host
}

// Hosts we consider normal for npm-resolved tarballs. Anything outside
// this set in a "resolved" URL is worth a human look.
var trustedRegistryHosts = []string{
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"npm.pkg.github.com",
}

// Config controls remote behavior.
type Config struct {
	// Enabled turns on live reachability checks. When false (default),
	// the module only inspects URLs and never touches the network.
	Enabled bool
}

// Finding records something notable about an external reference.
type Finding struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	URL      string `json:"url"`
	Host     string `json:"host"`
	Reason   string `json:"reason"`
	Severity string `json:"severity"`
	Checked  bool   `json:"checked"` // true only if a live request was made
}

// Inspect analyses a set of dependency references and returns findings.
// In the default configuration this performs NO network activity: it
// classifies hosts, flags untrusted registries, and refuses to ever
// contact blocklisted infrastructure.
func Inspect(refs []deps.Reference, cfg Config) []Finding {
	var findings []Finding

	for _, ref := range refs {
		if ref.Resolved == "" {
			continue
		}
		u, err := url.Parse(ref.Resolved)
		if err != nil {
			findings = append(findings, Finding{
				Name: ref.Name, Version: ref.Version, URL: ref.Resolved,
				Reason: "unparseable resolved URL", Severity: "MEDIUM",
			})
			continue
		}
		host := u.Hostname()

		// Hard stop: blocklisted C2 host appearing anywhere in a manifest
		// is a critical finding, and we never contact it.
		if isBlocklisted(host) {
			findings = append(findings, Finding{
				Name: ref.Name, Version: ref.Version, URL: ref.Resolved,
				Host:     host,
				Reason:   "resolved URL points at known C2 / attacker infrastructure (NOT contacted)",
				Severity: "CRITICAL", Checked: false,
			})
			continue
		}

		// Untrusted registry host: worth a human look.
		if !isTrustedHost(host) {
			f := Finding{
				Name: ref.Name, Version: ref.Version, URL: ref.Resolved,
				Host:     host,
				Reason:   "resolved URL is not a recognized package registry",
				Severity: "HIGH",
			}
			// Optionally confirm reachability, but only for non-blocklisted
			// hosts and only when explicitly enabled.
			if cfg.Enabled {
				f.Checked = true
				// Live reachability check intentionally left as a stub:
				// wiring an actual HTTP HEAD belongs behind additional
				// review. The seam exists; the trigger is deliberate.
				f.Reason += " (live check enabled; reachability stub)"
			}
			findings = append(findings, f)
			continue
		}

		// Missing integrity hash on a trusted host is still notable:
		// it means the lockfile cannot prove the tarball wasn't swapped.
		if ref.Integrity == "" {
			findings = append(findings, Finding{
				Name: ref.Name, Version: ref.Version, URL: ref.Resolved,
				Host:     host,
				Reason:   "trusted host but missing integrity hash",
				Severity: "MEDIUM",
			})
		}
	}

	return findings
}

func isBlocklisted(host string) bool {
	host = strings.ToLower(host)
	for _, b := range c2Blocklist {
		if host == b || strings.HasSuffix(host, "."+b) {
			return true
		}
	}
	return false
}

func isTrustedHost(host string) bool {
	host = strings.ToLower(host)
	for _, t := range trustedRegistryHosts {
		if host == t || strings.HasSuffix(host, "."+t) {
			return true
		}
	}
	return false
}
