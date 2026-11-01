package protected

import "strings"

var segments = map[string]struct{}{
	"windows":                   {},
	"program files":             {},
	"program files (x86)":       {},
	"system volume information": {},
	"$recycle.bin":              {},
	"windows.old":               {},
}

var names = map[string]struct{}{
	"pagefile.sys": {},
	"hiberfil.sys": {},
	"swapfile.sys": {},
	"bootmgr":      {},
	"ntldr":        {},
}

func IsPath(abs string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(abs, "/", `\`))
	switch {
	case strings.HasPrefix(normalized, `\\?\unc\`):
		normalized = `\\` + normalized[len(`\\?\unc\`):]
	case strings.HasPrefix(normalized, `\\?\`):
		normalized = normalized[len(`\\?\`):]
	}
	normalized = strings.TrimRight(normalized, `\`)
	parts := strings.Split(strings.Trim(normalized, `\`), `\`)
	if len(parts) == 0 {
		return false
	}
	if _, ok := names[parts[len(parts)-1]]; ok {
		return true
	}
	for i, part := range parts {
		if _, ok := segments[part]; ok {
			return true
		}
		if i == 1 && strings.HasSuffix(parts[0], ":") && part == "recovery" {
			return true
		}
	}
	return false
}

func IsDriveRoot(root string) bool {
	p := strings.TrimRight(strings.ToLower(strings.ReplaceAll(root, "/", `\`)), `\`)
	return len(p) == 2 && p[1] == ':'
}
