package dupes

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/JoyousJohn/scoria/internal/aggregate"
	"github.com/JoyousJohn/scoria/internal/protected"
)

const (
	DefaultMinBytes    = int64(1 << 20)
	DefaultPrefixBytes = int64(8 << 10)
	DefaultMaxExamples = 20
)

type Options struct {
	Root        string
	MinBytes    int64
	PrefixBytes int64
	MaxExamples int
}

type Group struct {
	Size   int64
	Count  int
	Wasted int64
	Paths  []string
}

type Result struct {
	Groups           []Group
	Candidates       uint64
	Hashed           uint64
	BytesRead        int64
	ReadErrors       uint64
	SkippedProtected uint64
	SkippedHardlinks uint64
}

type entry struct {
	path string
	size int64
}

type prefixKey struct {
	size int64
	sum  [32]byte
}

type fileID struct {
	volume uint32
	index  uint64
}

type Collector struct {
	mu   sync.Mutex
	opts Options

	sizes  map[int64]uint64
	prefix map[prefixKey][]entry
	links  map[fileID]struct{}

	candidates       atomic.Uint64
	hashed           atomic.Uint64
	bytesRead        atomic.Int64
	readErrors       atomic.Uint64
	skippedProtected atomic.Uint64
	skippedHardlinks atomic.Uint64
}

func NewCollector(sizeCounts []aggregate.SizeCount, opts Options) *Collector {
	if opts.MinBytes <= 0 {
		opts.MinBytes = DefaultMinBytes
	}
	if opts.PrefixBytes <= 0 {
		opts.PrefixBytes = DefaultPrefixBytes
	}
	if opts.MaxExamples <= 0 {
		opts.MaxExamples = DefaultMaxExamples
	}
	sizes := make(map[int64]uint64, len(sizeCounts))
	for _, sc := range sizeCounts {
		if sc.Count > 1 && sc.Size >= opts.MinBytes {
			sizes[sc.Size] = sc.Count
		}
	}
	return &Collector{
		opts:   opts,
		sizes:  sizes,
		prefix: make(map[prefixKey][]entry),
		links:  make(map[fileID]struct{}),
	}
}

func (c *Collector) CandidateCount() uint64 {
	return c.candidates.Load()
}

func (c *Collector) Sink(path string, size int64, modTime time.Time) {
	_ = modTime
	if size < c.opts.MinBytes || c.sizes[size] < 2 {
		return
	}
	if protected.IsPath(path) {
		c.skippedProtected.Add(1)
		return
	}

	file, err := os.Open(path)
	if err != nil {
		c.readErrors.Add(1)
		return
	}

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err == nil && info.NumberOfLinks > 1 {
		id := fileID{
			volume: info.VolumeSerialNumber,
			index:  uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
		}
		c.mu.Lock()
		_, seen := c.links[id]
		if !seen {
			c.links[id] = struct{}{}
		}
		c.mu.Unlock()
		if seen {
			c.skippedHardlinks.Add(1)
			file.Close()
			return
		}
	}

	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(file, c.opts.PrefixBytes))
	file.Close()
	if err != nil {
		c.readErrors.Add(1)
		return
	}

	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))
	key := prefixKey{size: size, sum: sum}

	c.mu.Lock()
	c.prefix[key] = append(c.prefix[key], entry{path: path, size: size})
	c.mu.Unlock()
	c.candidates.Add(1)
	c.bytesRead.Add(n)
}

func (c *Collector) Result() *Result {
	c.mu.Lock()
	prefix := c.prefix
	c.prefix = nil
	c.mu.Unlock()

	groups := make([]Group, 0)
	for key, entries := range prefix {
		if len(entries) < 2 {
			continue
		}
		full := make(map[[32]byte][]string, len(entries))
		for _, e := range entries {
			sum, n, err := hashFull(e.path)
			if err != nil {
				c.readErrors.Add(1)
				continue
			}
			full[sum] = append(full[sum], e.path)
			c.hashed.Add(1)
			c.bytesRead.Add(n)
		}
		for _, paths := range full {
			if len(paths) < 2 {
				continue
			}
			sort.Strings(paths)
			examples := make([]string, 0, min(len(paths), c.opts.MaxExamples))
			for _, path := range paths {
				if len(examples) >= c.opts.MaxExamples {
					break
				}
				examples = append(examples, c.relative(path))
			}
			groups = append(groups, Group{
				Size:   key.size,
				Count:  len(paths),
				Wasted: int64(len(paths)-1) * key.size,
				Paths:  examples,
			})
		}
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Wasted != groups[j].Wasted {
			return groups[i].Wasted > groups[j].Wasted
		}
		if groups[i].Size != groups[j].Size {
			return groups[i].Size > groups[j].Size
		}
		return firstPath(groups[i]) < firstPath(groups[j])
	})

	return &Result{
		Groups:           groups,
		Candidates:       c.candidates.Load(),
		Hashed:           c.hashed.Load(),
		BytesRead:        c.bytesRead.Load(),
		ReadErrors:       c.readErrors.Load(),
		SkippedProtected: c.skippedProtected.Load(),
		SkippedHardlinks: c.skippedHardlinks.Load(),
	}
}

func hashFull(path string) ([32]byte, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return [32]byte{}, 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	n, err := io.Copy(hasher, file)
	if err != nil {
		return [32]byte{}, n, err
	}
	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))
	return sum, n, nil
}

func (c *Collector) relative(path string) string {
	if c.opts.Root == "" {
		return path
	}
	rel, err := filepath.Rel(c.opts.Root, path)
	if err != nil {
		return path
	}
	return rel
}

func firstPath(g Group) string {
	if len(g.Paths) == 0 {
		return ""
	}
	return g.Paths[0]
}
