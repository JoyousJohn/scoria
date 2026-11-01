package aggregate

import (
	"sort"
	"sync"
	"time"
)

type FileEntry struct {
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

type DirEntry struct {
	Path  string `json:"path"`
	Files uint64 `json:"files"`
	Bytes int64  `json:"bytes"`
}

type ExtEntry struct {
	Ext   string `json:"ext"`
	Files uint64 `json:"files"`
	Bytes int64  `json:"bytes"`
}

type JunkEntry struct {
	Kind    string `json:"kind"`
	Files   uint64 `json:"files"`
	Bytes   int64  `json:"bytes"`
	Example string `json:"example,omitempty"`
}

type ExclusionEntry struct {
	Rule      string `json:"rule"`
	Kind      string `json:"kind"`
	Sensitive bool   `json:"sensitive"`
	Files     uint64 `json:"files"`
	Dirs      uint64 `json:"dirs"`
	Bytes     int64  `json:"bytes"`
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

type SizeCount struct {
	Size  int64  `json:"size"`
	Count uint64 `json:"count"`
}

type Aggregate struct {
	Totals      Totals           `json:"totals"`
	Extensions  []ExtEntry       `json:"extensions"`
	SizeCounts  []SizeCount      `json:"size_counts"`
	Largest     []FileEntry      `json:"largest"`
	Stalest     []FileEntry      `json:"stalest"`
	Directories []DirEntry       `json:"directories"`
	Junk        []JunkEntry      `json:"junk"`
	Excluded    []ExclusionEntry `json:"excluded"`
	Skipped     Skipped          `json:"skipped"`
}

type Shard struct {
	topN     int
	totals   Totals
	ext      map[string]*ExtEntry
	sizes    map[int64]uint64
	largest  []FileEntry
	stalest  []FileEntry
	dirs     []DirEntry
	junk     map[string]*JunkEntry
	excluded map[string]*ExclusionEntry
	skipped  Skipped
}

func NewShard(topN int) *Shard {
	if topN < 0 {
		topN = 0
	}
	return &Shard{
		topN:     topN,
		ext:      make(map[string]*ExtEntry),
		sizes:    make(map[int64]uint64),
		junk:     make(map[string]*JunkEntry),
		excluded: make(map[string]*ExclusionEntry),
	}
}

func (s *Shard) AddFile(dirRel, name, ext string, size int64, modTime time.Time, unique bool) {
	s.totals.Entries++
	s.totals.Files++
	s.totals.LogicalBytes += size
	if unique {
		s.totals.UniqueFiles++
		s.totals.UniqueBytes += size
	} else {
		s.totals.HardlinkExtra++
	}
	if size == 0 {
		s.totals.EmptyFiles++
	}

	e := s.ext[ext]
	if e == nil {
		e = &ExtEntry{Ext: ext}
		s.ext[ext] = e
	}
	e.Files++
	e.Bytes += size

	s.sizes[size]++

	if s.topN == 0 {
		return
	}
	keepSize := len(s.largest) < s.topN || size > s.largest[len(s.largest)-1].Size
	keepTime := len(s.stalest) < s.topN || modTime.Before(s.stalest[len(s.stalest)-1].ModTime)
	if !keepSize && !keepTime {
		return
	}
	entry := FileEntry{Path: joinRel(dirRel, name), Size: size, ModTime: modTime}
	if keepSize {
		s.largest = insertLargest(s.largest, s.topN, entry)
	}
	if keepTime {
		s.stalest = insertStalest(s.stalest, s.topN, entry)
	}
}

func (s *Shard) AddDir(rel string, files uint64, bytes int64) {
	s.totals.Directories++
	if s.topN == 0 {
		return
	}
	if rel == "" {
		rel = "."
	}
	if len(s.dirs) < s.topN || bytes > s.dirs[len(s.dirs)-1].Bytes {
		s.dirs = insertDir(s.dirs, s.topN, DirEntry{Path: rel, Files: files, Bytes: bytes})
	}
}

func (s *Shard) AddJunkDir(kind, rel string) {
	e := s.junk[kind]
	if e == nil {
		e = &JunkEntry{Kind: kind}
		s.junk[kind] = e
	}
	if e.Example == "" {
		e.Example = rel
	}
}

func (s *Shard) AddJunkFile(kind string, size int64) {
	e := s.junk[kind]
	if e == nil {
		e = &JunkEntry{Kind: kind}
		s.junk[kind] = e
	}
	e.Files++
	e.Bytes += size
}

func (s *Shard) AddExcluded(key, label, kind string, sensitive, isDir bool, size int64) {
	e := s.excluded[key]
	if e == nil {
		e = &ExclusionEntry{Rule: label, Kind: kind, Sensitive: sensitive}
		s.excluded[key] = e
	}
	if isDir {
		e.Dirs++
		return
	}
	e.Files++
	e.Bytes += size
}

func (s *Shard) SkipReparse(isDir bool) {
	s.skipped.ReparsePoints++
	if isDir {
		s.skipped.ReparsePointDirs++
	} else {
		s.skipped.ReparsePointFiles++
	}
}

func (s *Shard) SkipPermissionDeniedDir() {
	s.skipped.PermissionDeniedDirs++
}

func (s *Shard) SkipFileAccessDenied() {
	s.skipped.FileAccessDenied++
}

func (s *Shard) SkipFileOpenError() {
	s.skipped.FileOpenErrors++
}

func (s *Shard) SkipPlaceholder(size int64) {
	s.skipped.CloudPlaceholders++
	s.skipped.CloudPlaceholderBytes += size
}

func (s *Shard) SkipLongPath() {
	s.skipped.LongPathNames++
}

func (s *Shard) SkipOtherError() {
	s.skipped.OtherErrors++
}

type Collector struct {
	mu       sync.Mutex
	topN     int
	totals   Totals
	ext      map[string]*ExtEntry
	sizes    map[int64]uint64
	largest  []FileEntry
	stalest  []FileEntry
	dirs     []DirEntry
	junk     map[string]*JunkEntry
	excluded map[string]*ExclusionEntry
	skipped  Skipped
}

func NewCollector(topN int) *Collector {
	if topN < 0 {
		topN = 0
	}
	return &Collector{
		topN:     topN,
		ext:      make(map[string]*ExtEntry),
		sizes:    make(map[int64]uint64),
		junk:     make(map[string]*JunkEntry),
		excluded: make(map[string]*ExclusionEntry),
	}
}

func (c *Collector) Merge(s *Shard) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.totals.Entries += s.totals.Entries
	c.totals.UniqueFiles += s.totals.UniqueFiles
	c.totals.LogicalBytes += s.totals.LogicalBytes
	c.totals.UniqueBytes += s.totals.UniqueBytes
	c.totals.Files += s.totals.Files
	c.totals.Directories += s.totals.Directories
	c.totals.EmptyFiles += s.totals.EmptyFiles
	c.totals.HardlinkExtra += s.totals.HardlinkExtra

	for key, v := range s.ext {
		e := c.ext[key]
		if e == nil {
			e = &ExtEntry{Ext: v.Ext}
			c.ext[key] = e
		}
		e.Files += v.Files
		e.Bytes += v.Bytes
	}
	for size, count := range s.sizes {
		c.sizes[size] += count
	}
	for _, entry := range s.largest {
		c.largest = insertLargest(c.largest, c.topN, entry)
	}
	for _, entry := range s.stalest {
		c.stalest = insertStalest(c.stalest, c.topN, entry)
	}
	for _, entry := range s.dirs {
		c.dirs = insertDir(c.dirs, c.topN, entry)
	}
	for key, v := range s.junk {
		e := c.junk[key]
		if e == nil {
			e = &JunkEntry{Kind: v.Kind}
			c.junk[key] = e
		}
		e.Files += v.Files
		e.Bytes += v.Bytes
		if e.Example == "" {
			e.Example = v.Example
		}
	}
	for key, v := range s.excluded {
		e := c.excluded[key]
		if e == nil {
			e = &ExclusionEntry{Rule: v.Rule, Kind: v.Kind, Sensitive: v.Sensitive}
			c.excluded[key] = e
		}
		e.Files += v.Files
		e.Dirs += v.Dirs
		e.Bytes += v.Bytes
	}
	c.skipped.ReparsePoints += s.skipped.ReparsePoints
	c.skipped.ReparsePointFiles += s.skipped.ReparsePointFiles
	c.skipped.ReparsePointDirs += s.skipped.ReparsePointDirs
	c.skipped.PermissionDeniedDirs += s.skipped.PermissionDeniedDirs
	c.skipped.FileAccessDenied += s.skipped.FileAccessDenied
	c.skipped.FileOpenErrors += s.skipped.FileOpenErrors
	c.skipped.CloudPlaceholders += s.skipped.CloudPlaceholders
	c.skipped.CloudPlaceholderBytes += s.skipped.CloudPlaceholderBytes
	c.skipped.LongPathNames += s.skipped.LongPathNames
	c.skipped.OtherErrors += s.skipped.OtherErrors
}

func (c *Collector) Snapshot() *Aggregate {
	c.mu.Lock()
	defer c.mu.Unlock()

	extensions := make([]ExtEntry, 0, len(c.ext))
	for _, e := range c.ext {
		extensions = append(extensions, *e)
	}
	sort.Slice(extensions, func(i, j int) bool {
		if extensions[i].Bytes != extensions[j].Bytes {
			return extensions[i].Bytes > extensions[j].Bytes
		}
		return extensions[i].Ext < extensions[j].Ext
	})

	sizes := make([]SizeCount, 0, len(c.sizes))
	for size, count := range c.sizes {
		sizes = append(sizes, SizeCount{Size: size, Count: count})
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i].Size < sizes[j].Size })

	excluded := make([]ExclusionEntry, 0, len(c.excluded))
	for _, e := range c.excluded {
		excluded = append(excluded, *e)
	}
	sort.Slice(excluded, func(i, j int) bool {
		if excluded[i].Bytes != excluded[j].Bytes {
			return excluded[i].Bytes > excluded[j].Bytes
		}
		return excluded[i].Rule < excluded[j].Rule
	})

	junk := make([]JunkEntry, 0, len(c.junk))
	for _, e := range c.junk {
		junk = append(junk, *e)
	}
	sort.Slice(junk, func(i, j int) bool {
		if junk[i].Bytes != junk[j].Bytes {
			return junk[i].Bytes > junk[j].Bytes
		}
		return junk[i].Kind < junk[j].Kind
	})

	largest := append([]FileEntry(nil), c.largest...)
	sort.Slice(largest, func(i, j int) bool {
		if largest[i].Size != largest[j].Size {
			return largest[i].Size > largest[j].Size
		}
		return largest[i].Path < largest[j].Path
	})

	stalest := append([]FileEntry(nil), c.stalest...)
	sort.Slice(stalest, func(i, j int) bool {
		if !stalest[i].ModTime.Equal(stalest[j].ModTime) {
			return stalest[i].ModTime.Before(stalest[j].ModTime)
		}
		return stalest[i].Path < stalest[j].Path
	})

	dirs := append([]DirEntry(nil), c.dirs...)
	sort.Slice(dirs, func(i, j int) bool {
		if dirs[i].Bytes != dirs[j].Bytes {
			return dirs[i].Bytes > dirs[j].Bytes
		}
		return dirs[i].Path < dirs[j].Path
	})

	return &Aggregate{
		Totals:      c.totals,
		Extensions:  extensions,
		SizeCounts:  sizes,
		Largest:     largest,
		Stalest:     stalest,
		Directories: dirs,
		Junk:        junk,
		Excluded:    excluded,
		Skipped:     c.skipped,
	}
}

func joinRel(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + `\` + name
}

func insertLargest(list []FileEntry, n int, e FileEntry) []FileEntry {
	if n == 0 {
		return list
	}
	if len(list) >= n && e.Size <= list[len(list)-1].Size {
		return list
	}
	i := sort.Search(len(list), func(i int) bool { return list[i].Size < e.Size })
	list = append(list, FileEntry{})
	copy(list[i+1:], list[i:])
	list[i] = e
	if len(list) > n {
		list = list[:n]
	}
	return list
}

func insertStalest(list []FileEntry, n int, e FileEntry) []FileEntry {
	if n == 0 {
		return list
	}
	if len(list) >= n && !e.ModTime.Before(list[len(list)-1].ModTime) {
		return list
	}
	i := sort.Search(len(list), func(i int) bool { return list[i].ModTime.After(e.ModTime) })
	list = append(list, FileEntry{})
	copy(list[i+1:], list[i:])
	list[i] = e
	if len(list) > n {
		list = list[:n]
	}
	return list
}

func insertDir(list []DirEntry, n int, e DirEntry) []DirEntry {
	if n == 0 {
		return list
	}
	if len(list) >= n && e.Bytes <= list[len(list)-1].Bytes {
		return list
	}
	i := sort.Search(len(list), func(i int) bool { return list[i].Bytes < e.Bytes })
	list = append(list, DirEntry{})
	copy(list[i+1:], list[i:])
	list[i] = e
	if len(list) > n {
		list = list[:n]
	}
	return list
}
