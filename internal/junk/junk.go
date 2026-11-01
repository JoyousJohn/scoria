package junk

import "strings"

const (
	NodeModules = "node_modules"
	PyCache     = "__pycache__"
	Venv        = ".venv"
	VenvPlain   = "venv"
	PytestCache = ".pytest_cache"
	MypyCache   = ".mypy_cache"
	RuffCache   = ".ruff_cache"
	Gradle      = ".gradle"
	Next        = ".next"
	Nuxt        = ".nuxt"
	Turbo       = ".turbo"
	Cache       = ".cache"
	Build       = "build"
	Dist        = "dist"
	Target      = "target"
	Obj         = "obj"
	Bin         = "bin"
)

var names = map[string]string{
	"node_modules":  NodeModules,
	"__pycache__":   PyCache,
	".venv":         Venv,
	"venv":          VenvPlain,
	".pytest_cache": PytestCache,
	".mypy_cache":   MypyCache,
	".ruff_cache":   RuffCache,
	".gradle":       Gradle,
	".next":         Next,
	".nuxt":         Nuxt,
	".turbo":        Turbo,
	".cache":        Cache,
	"build":         Build,
	"dist":          Dist,
	"target":        Target,
	"obj":           Obj,
	"bin":           Bin,
}

func ClassifyDir(name string) (string, bool) {
	kind, ok := names[strings.ToLower(name)]
	return kind, ok
}

func IsGenerated(kind string) bool {
	switch kind {
	case Build, Dist, Target, Obj, Bin:
		return true
	default:
		return false
	}
}
