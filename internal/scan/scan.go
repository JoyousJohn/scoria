//go:build windows

package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/JoyousJohn/scoria/internal/aggregate"
	"github.com/JoyousJohn/scoria/internal/exclude"
	"github.com/JoyousJohn/scoria/internal/junk"
	"github.com/JoyousJohn/scoria/internal/protected"
)

const maxPathUnits = 32767

type Options struct {
	Root       string
	Workers    int
	TopN       int
	CountLinks bool
	Progress   func(Progress)
	FileSink   func(path string, size int64, modTime time.Time)
}

type Progress struct {
	Entries          uint64
	Directories      uint64
	Elapsed          time.Duration
	EntriesPerSecond float64
}

type Result struct {
	Root      string
	Workers   int
	Aggregate *aggregate.Aggregate
	Elapsed   time.Duration
}

type workerCounters struct {
	entries atomic.Uint64
	dirs    atomic.Uint64
}

func snapshotProgress(counters []workerCounters, start time.Time) Progress {
	var entries, dirs uint64
	for i := range counters {
		entries += counters[i].entries.Load()
		dirs += counters[i].dirs.Load()
	}
	elapsed := time.Since(start)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(entries) / elapsed.Seconds()
	}
	return Progress{
		Entries:          entries,
		Directories:      dirs,
		Elapsed:          elapsed,
		EntriesPerSecond: rate,
	}
}

type dirTask struct {
	path []uint16
	rel  string
	abs  string
	junk string
}

type dirQueue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	items   []dirTask
	pending int
}

func newDirQueue(root dirTask) *dirQueue {
	q := &dirQueue{items: []dirTask{root}, pending: 1}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *dirQueue) push(task dirTask) {
	q.mu.Lock()
	q.items = append(q.items, task)
	q.pending++
	q.cond.Signal()
	q.mu.Unlock()
}

func (q *dirQueue) pop() (dirTask, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if n := len(q.items); n > 0 {
			task := q.items[n-1]
			q.items = q.items[:n-1]
			return task, true
		}
		if q.pending == 0 {
			return dirTask{}, false
		}
		q.cond.Wait()
	}
}

func (q *dirQueue) done() {
	q.mu.Lock()
	q.pending--
	if q.pending == 0 {
		q.cond.Broadcast()
	}
	q.mu.Unlock()
}

type worker struct {
	matcher    *exclude.Matcher
	collector  *aggregate.Collector
	hardlinks  *hardlinkSet
	queue      *dirQueue
	topN       int
	countLinks bool
	progress   *workerCounters
	sink       func(path string, size int64, modTime time.Time)
	patternBuf []uint16
	fileBuf    []uint16
	data       findData
}

func Walk(opts Options) (*Result, error) {
	start := time.Now()

	abs, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("scan: %s is not a directory", abs)
	}

	matcher, err := exclude.Compile(exclude.DefaultRules())
	if err != nil {
		return nil, err
	}
	if rule, ok := matcher.MatchDir(abs, ""); ok {
		return nil, fmt.Errorf("scan: root %s is excluded by rule %s", abs, rule.Label)
	}

	rootPath, err := utf16Path(prefixed(abs))
	if err != nil {
		return nil, err
	}

	topN := opts.TopN
	if topN < 0 {
		topN = 0
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}

	rootJunk, _ := junk.ClassifyDir(filepath.Base(abs))
	if protected.IsPath(abs) {
		rootJunk = ""
	}
	queue := newDirQueue(dirTask{path: rootPath, abs: abs, junk: rootJunk})
	collector := aggregate.NewCollector(topN)
	links := newHardlinkSet()

	var counters []workerCounters
	var progressStop chan struct{}
	var progressDone chan struct{}
	if opts.Progress != nil {
		counters = make([]workerCounters, workers)
		progressStop = make(chan struct{})
		progressDone = make(chan struct{})
		go func() {
			defer close(progressDone)
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					opts.Progress(snapshotProgress(counters, start))
				case <-progressStop:
					return
				}
			}
		}()
	}

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		var pc *workerCounters
		if counters != nil {
			pc = &counters[i]
		}
		w := &worker{
			matcher:    matcher,
			collector:  collector,
			hardlinks:  links,
			queue:      queue,
			topN:       topN,
			countLinks: opts.CountLinks,
			progress:   pc,
			sink:       opts.FileSink,
		}
		go func() {
			defer wg.Done()
			w.run()
		}()
	}
	wg.Wait()
	if progressStop != nil {
		close(progressStop)
		<-progressDone
	}

	return &Result{
		Root:      abs,
		Workers:   workers,
		Aggregate: collector.Snapshot(),
		Elapsed:   time.Since(start),
	}, nil
}

func (w *worker) run() {
	for {
		task, ok := w.queue.pop()
		if !ok {
			return
		}
		w.walkDir(task)
		w.queue.done()
	}
}

func (w *worker) walkDir(task dirTask) {
	if w.progress != nil {
		w.progress.dirs.Add(1)
	}
	shard := aggregate.NewShard(w.topN)
	var directFiles uint64
	var directBytes int64
	defer func() {
		shard.AddDir(task.rel, directFiles, directBytes)
		w.collector.Merge(shard)
	}()

	w.patternBuf = buildPattern(w.patternBuf, task.path)
	handle, err := findFirst(&w.patternBuf[0], &w.data)
	if err != nil {
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_NO_MORE_FILES):
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			shard.SkipPermissionDeniedDir()
		case errors.Is(err, windows.ERROR_FILENAME_EXCED_RANGE):
			shard.SkipLongPath()
		default:
			shard.SkipOtherError()
		}
		return
	}
	defer windows.FindClose(handle)

	for {
		n := w.data.nameLen()
		switch {
		case n == 0 || n >= len(w.data.FileName):
			shard.SkipLongPath()
		case isDotEntry(w.data.FileName[:n]):
		default:
			if w.progress != nil {
				w.progress.entries.Add(1)
			}
			w.handleEntry(task, shard, n, &directFiles, &directBytes)
		}

		more, err := findNext(handle, &w.data)
		if err != nil {
			shard.SkipOtherError()
			return
		}
		if !more {
			return
		}
	}
}

func (w *worker) handleEntry(task dirTask, shard *aggregate.Shard, n int, directFiles *uint64, directBytes *int64) {
	name := windows.UTF16ToString(w.data.FileName[:n])
	attrs := w.data.FileAttributes

	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		shard.SkipReparse(attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0)
		return
	}

	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		rel := joinRel(task.rel, name)
		abs := joinAbs(task.abs, name)
		if rule, ok := w.matcher.MatchDir(abs, rel); ok {
			shard.AddExcluded(rule.Key(), rule.Label, string(rule.Kind), rule.Sensitive, true, 0)
			return
		}
		if len(task.path)+1+n+1 > maxPathUnits {
			shard.SkipLongPath()
			return
		}
		junkKind := task.junk
		if junkKind == "" {
			if kind, ok := junk.ClassifyDir(name); ok && !protected.IsPath(abs) {
				junkKind = kind
				shard.AddJunkDir(kind, rel)
			}
		}
		w.queue.push(childTask(task, name, w.data.FileName[:n], junkKind))
		return
	}

	size := w.data.size()
	ext := extension(name)
	rel := ""
	if w.matcher.NeedsRelPath() {
		rel = joinRel(task.rel, name)
	}
	if rule, ok := w.matcher.MatchFile(name, ext, rel); ok {
		shard.AddExcluded(rule.Key(), rule.Label, string(rule.Kind), rule.Sensitive, false, size)
		return
	}

	unique := true
	placeholder := attrs&(windows.FILE_ATTRIBUTE_OFFLINE|
		windows.FILE_ATTRIBUTE_RECALL_ON_OPEN|
		windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) != 0
	if placeholder {
		shard.SkipPlaceholder(size)
	} else if w.countLinks {
		if len(task.path)+1+n+1 > maxPathUnits {
			shard.SkipLongPath()
		} else {
			w.fileBuf = buildFilePath(w.fileBuf, task.path, w.data.FileName[:n])
			links, id, err := fileLinkInfo(&w.fileBuf[0])
			if err != nil {
				if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
					shard.SkipFileAccessDenied()
				} else {
					shard.SkipFileOpenError()
				}
			} else if links > 1 {
				if !w.hardlinks.add(id) {
					unique = false
				}
			}
		}
	}

	modTime := w.data.modTime()
	shard.AddFile(task.rel, name, ext, size, modTime, unique)
	if task.junk != "" {
		shard.AddJunkFile(task.junk, size)
	}
	if w.sink != nil && !placeholder {
		w.sink(joinAbs(task.abs, name), size, modTime)
	}
	*directFiles = *directFiles + 1
	*directBytes += size
}

func childTask(parent dirTask, name string, nameUTF16 []uint16, junkKind string) dirTask {
	path := make([]uint16, 0, len(parent.path)+1+len(nameUTF16))
	path = append(path, parent.path...)
	if len(path) == 0 || path[len(path)-1] != '\\' {
		path = append(path, '\\')
	}
	path = append(path, nameUTF16...)
	return dirTask{
		path: path,
		rel:  joinRel(parent.rel, name),
		abs:  joinAbs(parent.abs, name),
		junk: junkKind,
	}
}

func buildPattern(buf []uint16, dir []uint16) []uint16 {
	buf = append(buf[:0], dir...)
	if len(buf) == 0 || buf[len(buf)-1] != '\\' {
		buf = append(buf, '\\')
	}
	return append(buf, '*', 0)
}

func buildFilePath(buf []uint16, dir []uint16, name []uint16) []uint16 {
	buf = append(buf[:0], dir...)
	if len(buf) == 0 || buf[len(buf)-1] != '\\' {
		buf = append(buf, '\\')
	}
	buf = append(buf, name...)
	return append(buf, 0)
}

func utf16Path(s string) ([]uint16, error) {
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	return u[:len(u)-1], nil
}

func prefixed(abs string) string {
	switch {
	case strings.HasPrefix(abs, `\\?\`), strings.HasPrefix(abs, `\\.\`):
		return abs
	case strings.HasPrefix(abs, `\\`):
		return `\\?\UNC\` + abs[2:]
	default:
		return `\\?\` + abs
	}
}

func isDotEntry(name []uint16) bool {
	if len(name) == 1 && name[0] == '.' {
		return true
	}
	return len(name) == 2 && name[0] == '.' && name[1] == '.'
}

func extension(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		switch name[i] {
		case '\\', '/':
			return ""
		case '.':
			if i == 0 || i == len(name)-1 {
				return ""
			}
			return strings.ToLower(name[i:])
		}
	}
	return ""
}

func joinRel(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + `\` + name
}

func joinAbs(dir, name string) string {
	if strings.HasSuffix(dir, `\`) {
		return dir + name
	}
	return dir + `\` + name
}
