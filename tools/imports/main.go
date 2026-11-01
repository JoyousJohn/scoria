package main

import (
	"debug/pe"
	"fmt"
	"os"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: imports <pe-file>")
		os.Exit(2)
	}
	file, err := pe.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "imports:", err)
		os.Exit(2)
	}
	defer file.Close()

	symbols, err := file.ImportedSymbols()
	if err != nil {
		fmt.Fprintln(os.Stderr, "imports:", err)
		os.Exit(2)
	}

	byLibrary := make(map[string][]string)
	for _, symbol := range symbols {
		parts := strings.SplitN(symbol, ":", 2)
		if len(parts) != 2 {
			byLibrary["?"] = append(byLibrary["?"], symbol)
			continue
		}
		byLibrary[parts[1]] = append(byLibrary[parts[1]], parts[0])
	}

	libraries := make([]string, 0, len(byLibrary))
	for library := range byLibrary {
		libraries = append(libraries, library)
	}
	sort.Strings(libraries)
	for _, library := range libraries {
		names := byLibrary[library]
		sort.Strings(names)
		fmt.Println(library)
		seen := make(map[string]struct{}, len(names))
		for _, name := range names {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			fmt.Printf("  %s\n", name)
		}
	}
}
