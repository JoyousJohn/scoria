package rules

import "path/filepath"

func absolute(root, rel string) string {
	if rel == "" {
		return root
	}
	return filepath.Join(root, rel)
}
