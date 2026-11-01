package digest

import (
	"time"

	"github.com/JoyousJohn/scoria/internal/aggregate"
)

const Version = 1

type Scan struct {
	Workers          int     `json:"workers"`
	TopN             int     `json:"top_n"`
	CountLinks       bool    `json:"count_links"`
	GoVersion        string  `json:"go_version"`
	ElapsedMS        int64   `json:"elapsed_ms"`
	EntriesPerSecond float64 `json:"entries_per_second"`
	Sort             string  `json:"sort"`
}

type Totals struct {
	Entries       uint64 `json:"entries"`
	UniqueFiles   uint64 `json:"unique_files"`
	LogicalBytes  int64  `json:"logical_bytes"`
	UniqueBytes   int64  `json:"unique_bytes"`
	Files         uint64 `json:"files"`
	Directories   uint64 `json:"directories"`
	EmptyFiles    uint64 `json:"empty_files"`
	HardlinkExtra uint64 `json:"hardlink_extra_entries"`
}

type File struct {
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

type Extension struct {
	Ext   string `json:"ext"`
	Files uint64 `json:"files"`
	Bytes int64  `json:"bytes"`
}

type Directory struct {
	Path  string `json:"path"`
	Files uint64 `json:"files"`
	Bytes int64  `json:"bytes"`
}

type SizeCount struct {
	Size  int64  `json:"size"`
	Count uint64 `json:"count"`
}

type Exclusion struct {
	Rule      string `json:"rule"`
	Kind      string `json:"kind"`
	Sensitive bool   `json:"sensitive"`
	Files     uint64 `json:"files"`
	Dirs      uint64 `json:"dirs"`
	Bytes     int64  `json:"bytes"`
}

type DuplicateCheck struct {
	Candidates       uint64 `json:"candidates"`
	Hashed           uint64 `json:"hashed"`
	BytesRead        int64  `json:"bytes_read"`
	ReadErrors       uint64 `json:"read_errors"`
	SkippedProtected uint64 `json:"skipped_protected"`
	SkippedHardlinks uint64 `json:"skipped_hardlinks"`
}

type Recommendation struct {
	ID         string   `json:"id"`
	Rule       string   `json:"rule"`
	Title      string   `json:"title"`
	Detail     string   `json:"detail"`
	Confidence string   `json:"confidence"`
	Priority   int      `json:"priority"`
	Items      uint64   `json:"items"`
	Bytes      int64    `json:"bytes"`
	Examples   []string `json:"examples,omitempty"`
}

type Skipped struct {
	ReparsePoints         uint64 `json:"reparse_points"`
	ReparsePointFiles     uint64 `json:"reparse_point_files"`
	ReparsePointDirs      uint64 `json:"reparse_point_dirs"`
	PermissionDeniedDirs  uint64 `json:"permission_denied_dirs"`
	FileAccessDenied      uint64 `json:"file_access_denied"`
	FileOpenErrors        uint64 `json:"file_open_errors"`
	CloudPlaceholders     uint64 `json:"cloud_placeholders"`
	CloudPlaceholderBytes int64  `json:"cloud_placeholder_bytes"`
	LongPathNames         uint64 `json:"long_path_names"`
	OtherErrors           uint64 `json:"other_errors"`
}

type AnalysisFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Rank        int    `json:"rank"`
	Explanation string `json:"explanation"`
}

type Analysis struct {
	Analyzer string            `json:"analyzer"`
	Model    string            `json:"model,omitempty"`
	Findings []AnalysisFinding `json:"findings"`
}

type Digest struct {
	Version         int              `json:"version"`
	GeneratedAt     time.Time        `json:"generated_at"`
	Root            string           `json:"root"`
	Scan            Scan             `json:"scan"`
	Totals          Totals           `json:"totals"`
	Extensions      []Extension      `json:"extensions"`
	Largest         []File           `json:"largest"`
	Stalest         []File           `json:"stalest"`
	Directories     []Directory      `json:"directories"`
	SizeCounts      []SizeCount      `json:"size_counts"`
	Excluded        []Exclusion      `json:"excluded"`
	Skipped         Skipped          `json:"skipped"`
	Recommendations []Recommendation `json:"recommendations"`
	DuplicateCheck  *DuplicateCheck  `json:"duplicate_check,omitempty"`
	Analysis        *Analysis        `json:"analysis,omitempty"`
}

func New(root string, generatedAt time.Time, agg *aggregate.Aggregate, scan Scan) *Digest {
	d := &Digest{
		Version:     Version,
		GeneratedAt: generatedAt,
		Root:        root,
		Scan:        scan,
		Totals: Totals{
			Entries:       agg.Totals.Entries,
			UniqueFiles:   agg.Totals.UniqueFiles,
			LogicalBytes:  agg.Totals.LogicalBytes,
			UniqueBytes:   agg.Totals.UniqueBytes,
			Files:         agg.Totals.Files,
			Directories:   agg.Totals.Directories,
			EmptyFiles:    agg.Totals.EmptyFiles,
			HardlinkExtra: agg.Totals.HardlinkExtra,
		},
		Extensions:      make([]Extension, 0, len(agg.Extensions)),
		Largest:         make([]File, 0, len(agg.Largest)),
		Stalest:         make([]File, 0, len(agg.Stalest)),
		Directories:     make([]Directory, 0, len(agg.Directories)),
		SizeCounts:      make([]SizeCount, 0, len(agg.SizeCounts)),
		Excluded:        make([]Exclusion, 0, len(agg.Excluded)),
		Recommendations: make([]Recommendation, 0),
		Skipped: Skipped{
			ReparsePoints:         agg.Skipped.ReparsePoints,
			ReparsePointFiles:     agg.Skipped.ReparsePointFiles,
			ReparsePointDirs:      agg.Skipped.ReparsePointDirs,
			PermissionDeniedDirs:  agg.Skipped.PermissionDeniedDirs,
			FileAccessDenied:      agg.Skipped.FileAccessDenied,
			FileOpenErrors:        agg.Skipped.FileOpenErrors,
			CloudPlaceholders:     agg.Skipped.CloudPlaceholders,
			CloudPlaceholderBytes: agg.Skipped.CloudPlaceholderBytes,
			LongPathNames:         agg.Skipped.LongPathNames,
			OtherErrors:           agg.Skipped.OtherErrors,
		},
	}
	for _, e := range agg.Extensions {
		d.Extensions = append(d.Extensions, Extension{Ext: e.Ext, Files: e.Files, Bytes: e.Bytes})
	}
	for _, f := range agg.Largest {
		d.Largest = append(d.Largest, File{Path: f.Path, Size: f.Size, ModTime: f.ModTime})
	}
	for _, f := range agg.Stalest {
		d.Stalest = append(d.Stalest, File{Path: f.Path, Size: f.Size, ModTime: f.ModTime})
	}
	for _, dir := range agg.Directories {
		d.Directories = append(d.Directories, Directory{Path: dir.Path, Files: dir.Files, Bytes: dir.Bytes})
	}
	for _, s := range agg.SizeCounts {
		d.SizeCounts = append(d.SizeCounts, SizeCount{Size: s.Size, Count: s.Count})
	}
	for _, e := range agg.Excluded {
		d.Excluded = append(d.Excluded, Exclusion{
			Rule: e.Rule, Kind: e.Kind, Sensitive: e.Sensitive,
			Files: e.Files, Dirs: e.Dirs, Bytes: e.Bytes,
		})
	}
	return d
}
