package remote

import (
	"strings"
	"testing"

	"github.com/daemon-labs-co/git-compromise-scanner/deps"
)

func findByName(fs []Finding, name string) *Finding {
	for i := range fs {
		if fs[i].Name == name {
			return &fs[i]
		}
	}
	return nil
}

func TestInspectClassification(t *testing.T) {
	refs := []deps.Reference{
		// No resolved URL: must be ignored entirely.
		{Name: "unresolved", Version: "1.0.0"},
		// Blocklisted host: CRITICAL, never contacted.
		{Name: "evil", Version: "6.6.6", Resolved: "https://c2.malicious.example/payload.tgz"},
		// Blocklisted subdomain: also CRITICAL.
		{Name: "evil-sub", Version: "6.6.7", Resolved: "https://cdn.c2.malicious.example/x.tgz"},
		// Untrusted registry host: HIGH.
		{Name: "weird", Version: "2.0.0", Resolved: "https://random-mirror.example.net/weird.tgz"},
		// Trusted host with integrity: no finding.
		{Name: "clean", Version: "1.3.0", Resolved: "https://registry.npmjs.org/clean/-/clean-1.3.0.tgz", Integrity: "sha512-abc"},
		// Trusted host without integrity: MEDIUM.
		{Name: "no-integrity", Version: "0.1.0", Resolved: "https://registry.npmjs.org/no-integrity/-/no-integrity-0.1.0.tgz"},
		// Unparseable URL: MEDIUM.
		{Name: "garbage", Version: "0.0.1", Resolved: "http://%zz"},
	}

	findings := Inspect(refs, Config{})
	if len(findings) != 5 {
		t.Fatalf("got %d findings, want 5: %+v", len(findings), findings)
	}

	if f := findByName(findings, "unresolved"); f != nil {
		t.Errorf("unresolved ref should produce no finding: %+v", f)
	}
	if f := findByName(findings, "clean"); f != nil {
		t.Errorf("trusted host with integrity should produce no finding: %+v", f)
	}

	for _, name := range []string{"evil", "evil-sub"} {
		f := findByName(findings, name)
		if f == nil {
			t.Fatalf("no finding for %s", name)
		}
		if f.Severity != "CRITICAL" || f.Checked {
			t.Errorf("%s = %+v, want CRITICAL and Checked=false", name, f)
		}
	}

	if f := findByName(findings, "weird"); f == nil || f.Severity != "HIGH" {
		t.Errorf("weird = %+v, want HIGH", f)
	}
	if f := findByName(findings, "no-integrity"); f == nil || f.Severity != "MEDIUM" {
		t.Errorf("no-integrity = %+v, want MEDIUM", f)
	}
	if f := findByName(findings, "garbage"); f == nil || f.Severity != "MEDIUM" {
		t.Errorf("garbage = %+v, want MEDIUM", f)
	}
}

func TestInspectLiveModeStaysStubbedAndBlocklistUnchecked(t *testing.T) {
	refs := []deps.Reference{
		{Name: "evil", Version: "1", Resolved: "https://c2.malicious.example/p.tgz"},
		{Name: "weird", Version: "1", Resolved: "https://unknown-host.example.org/p.tgz"},
	}
	findings := Inspect(refs, Config{Enabled: true})

	evil := findByName(findings, "evil")
	if evil == nil || evil.Checked {
		t.Errorf("blocklisted host must never be live-checked, even when enabled: %+v", evil)
	}

	weird := findByName(findings, "weird")
	if weird == nil || !weird.Checked {
		t.Fatalf("untrusted host should be marked Checked in live mode: %+v", weird)
	}
	if !strings.Contains(weird.Reason, "reachability stub") {
		t.Errorf("live check is a stub and the reason should say so: %q", weird.Reason)
	}
}

func TestIsBlocklisted(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"c2.malicious.example", true},
		{"C2.MALICIOUS.EXAMPLE", true},          // case-insensitive
		{"sub.c2.malicious.example", true},      // subdomain matches
		{"notc2.malicious.example.com", false},  // different registrable domain
		{"registry.npmjs.org", false},
	}
	for _, c := range cases {
		if got := isBlocklisted(c.host); got != c.want {
			t.Errorf("isBlocklisted(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestIsTrustedHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"registry.npmjs.org", true},
		{"REGISTRY.NPMJS.ORG", true},
		{"npm.pkg.github.com", true},
		{"evil-registry.npmjs.org.attacker.example", false}, // prefix spoof
		{"example.com", false},
	}
	for _, c := range cases {
		if got := isTrustedHost(c.host); got != c.want {
			t.Errorf("isTrustedHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}
