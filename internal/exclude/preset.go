package exclude

func DefaultRules() []Rule {
	subtrees := []string{
		`%USERPROFILE%\.ssh`,
		`%APPDATA%\1Password`,
		`%LOCALAPPDATA%\1Password`,
		`%APPDATA%\Bitwarden`,
		`%LOCALAPPDATA%\Bitwarden`,
		`%APPDATA%\Dashlane`,
		`%LOCALAPPDATA%\Dashlane`,
		`%APPDATA%\NordPass`,
		`%LOCALAPPDATA%\NordPass`,
		`%APPDATA%\Enpass`,
		`%LOCALAPPDATA%\Enpass`,
		`%APPDATA%\KeePassXC`,
		`%LOCALAPPDATA%\KeePassXC`,
		`%LOCALAPPDATA%\Google\Chrome\User Data`,
		`%LOCALAPPDATA%\Microsoft\Edge\User Data`,
		`%APPDATA%\Mozilla\Firefox\Profiles`,
		`%LOCALAPPDATA%\BraveSoftware`,
		`%LOCALAPPDATA%\Vivaldi`,
		`%LOCALAPPDATA%\Opera Software`,
		`%APPDATA%\Electrum`,
		`%APPDATA%\Ethereum`,
		`%APPDATA%\Bitcoin`,
		`%APPDATA%\Exodus`,
		`%APPDATA%\Ledger Live`,
		`%LOCALAPPDATA%\Ledger Live`,
		`%APPDATA%\Monero`,
		`%USERPROFILE%\.bitcoin`,
		`%USERPROFILE%\.ethereum`,
		`%USERPROFILE%\.monero`,
	}
	extensions := []string{".kdbx", ".pem", ".key"}
	globs := []string{"wallet.dat"}

	rules := make([]Rule, 0, len(subtrees)+len(extensions)+len(globs))
	for _, p := range subtrees {
		rules = append(rules, Rule{Kind: Subtree, Pattern: p, Sensitive: true})
	}
	for _, p := range extensions {
		rules = append(rules, Rule{Kind: Extension, Pattern: p, Sensitive: true})
	}
	for _, p := range globs {
		rules = append(rules, Rule{Kind: Glob, Pattern: p, Sensitive: true})
	}
	return rules
}
