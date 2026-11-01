package exclude

import "testing"

func mustCompile(t *testing.T, rules ...Rule) *Matcher {
	t.Helper()
	m, err := Compile(rules)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return m
}

func TestExtensionMatchIsCaseInsensitive(t *testing.T) {
	m := mustCompile(t, Rule{Kind: Extension, Pattern: ".KDBX", Label: "*.kdbx", Sensitive: true})
	if r, ok := m.MatchFile("Vault.KDBX", ".kdbx", ""); !ok {
		t.Fatal("expected .kdbx match")
	} else if r.Label != "*.kdbx" {
		t.Fatalf("label = %q", r.Label)
	}
	if _, ok := m.MatchFile("Vault.kdbx.bak", ".bak", ""); ok {
		t.Fatal("unexpected match")
	}
}

func TestSubtreeMatchHonoursBoundaryAndPrefix(t *testing.T) {
	m := mustCompile(t, Rule{Kind: Subtree, Pattern: `C:\Users\Me\Tax`})
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Users\Me\Tax`, true},
		{`C:\Users\Me\Tax\2024\return.pdf`, true},
		{`\\?\C:\Users\Me\Tax\2024\return.pdf`, true},
		{`c:\users\me\tax\2024\return.pdf`, true},
		{`C:\Users\Me\Taxes\return.pdf`, false},
		{`C:\Users\Me\Other\return.pdf`, false},
	}
	for _, tc := range cases {
		_, got := m.MatchDir(tc.path, "")
		if got != tc.want {
			t.Errorf("MatchDir(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestGlobMatchesBasenameCaseInsensitively(t *testing.T) {
	m := mustCompile(t, Rule{Kind: Glob, Pattern: "wallet.dat", Label: "wallet.dat", Sensitive: true})
	if _, ok := m.MatchFile("Wallet.DAT", ".dat", `wallets\Wallet.DAT`); !ok {
		t.Fatal("expected literal glob match")
	}
	if _, ok := m.MatchFile("wallet.dat.bak", ".bak", ""); ok {
		t.Fatal("unexpected match")
	}
}

func TestGlobPathRuleUsesRelativePath(t *testing.T) {
	m := mustCompile(t, Rule{Kind: Glob, Pattern: `Users/*/secrets`})
	if !m.NeedsRelPath() {
		t.Fatal("expected path glob")
	}
	if _, ok := m.MatchFile("a.txt", ".txt", `Users/anna/secrets/a.txt`); ok {
		t.Fatal("file rule should match the file name, not merely the parent")
	}
	if _, ok := m.MatchDir(`C:\Users\anna\secrets`, `Users\anna\secrets`); !ok {
		t.Fatal("expected directory glob match")
	}
}

func TestDefaultRulesAreSensitiveAndUseUnredactedLabels(t *testing.T) {
	rules := DefaultRules()
	if len(rules) == 0 {
		t.Fatal("no default rules")
	}
	foundSSH := false
	for _, r := range rules {
		if !r.Sensitive {
			t.Fatalf("rule %q is not sensitive", r.Pattern)
		}
		if r.Pattern == `%USERPROFILE%\.ssh` {
			foundSSH = true
		}
	}
	if !foundSSH {
		t.Fatal("missing .ssh preset")
	}
}

func TestSensitivePresetMatchesExpandedPath(t *testing.T) {
	t.Setenv("USERPROFILE", `C:\Users\Tester`)
	m := mustCompile(t, DefaultRules()...)
	if _, ok := m.MatchDir(`C:\Users\Tester\.ssh`, `.ssh`); !ok {
		t.Fatal("expected .ssh subtree match")
	}
	if _, ok := m.MatchFile("id_rsa", "", `.ssh\id_rsa`); ok {
		t.Fatal("extension-only check must not match an unrelated file")
	}
}
