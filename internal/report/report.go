package report

import (
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/JoyousJohn/scoria/internal/digest"
)

type view struct {
	*digest.Digest
	Extensions []digest.Extension
}

func Render(w io.Writer, doc *digest.Digest) error {
	d := view{
		Digest:     doc,
		Extensions: limitExtensions(doc.Extensions, 25),
	}
	return reportTemplate.Execute(w, d)
}

func limitExtensions(in []digest.Extension, n int) []digest.Extension {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func formatBytes(n int64) string {
	if n < 0 {
		return "-" + formatBytes(-n)
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	value := strconv.FormatFloat(float64(n)/float64(div), 'f', 2, 64)
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		value = addCommas(value[:dot]) + value[dot:]
	}
	return value + " " + string("KMGTPE"[exp]) + "iB"
}

func addCommas(s string) string {
	if len(s) <= 3 {
		return s
	}
	var b []byte
	head := len(s) % 3
	if head > 0 {
		b = append(b, s[:head]...)
	}
	for i := head; i < len(s); i += 3 {
		if len(b) > 0 {
			b = append(b, ',')
		}
		b = append(b, s[i:i+3]...)
	}
	return string(b)
}

func formatCount(n uint64) string {
	return addCommas(strconv.FormatUint(n, 10))
}

func formatRate(v float64) string {
	return addCommas(strconv.FormatUint(uint64(v), 10))
}

func formatDate(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format("2006-01-02")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format("2006-01-02 15:04:05")
}

func formatDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%d ms", ms)
	}
	return fmt.Sprintf("%.1f s", float64(ms)/1000)
}

func extensionLabel(ext string) string {
	if ext == "" {
		return "(none)"
	}
	return ext
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"bytes":    formatBytes,
	"num":      formatCount,
	"rate":     formatRate,
	"date":     formatDate,
	"datetime": formatTime,
	"duration": formatDuration,
	"ext":      extensionLabel,
}).Parse(reportHTML))

const reportHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Scoria report - {{.Root}}</title>
<style>
:root {
  color-scheme: dark light;
  --bg: #0f1115;
  --panel: #171a21;
  --panel-2: #1d212a;
  --text: #e8eaf0;
  --muted: #9aa3b2;
  --border: #2a303b;
  --accent: #7aa2f7;
  --low: #9aa3b2;
  --medium: #d6a14a;
  --high: #7aa2f7;
  --radius: 12px;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f6f7f9;
    --panel: #ffffff;
    --panel-2: #f0f2f5;
    --text: #171a21;
    --muted: #5c6675;
    --border: #d9dee7;
    --accent: #2f5fbf;
    --low: #5c6675;
    --medium: #9a6a12;
    --high: #2f5fbf;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
}
main { max-width: 1120px; margin: 0 auto; padding: 40px 24px 80px; }
header { border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 28px; }
.eyebrow { margin: 0 0 6px; color: var(--muted); font-size: 12px; letter-spacing: .12em; text-transform: uppercase; }
h1 { margin: 0 0 8px; font-size: 32px; letter-spacing: -0.02em; }
h2 { margin: 0; font-size: 19px; letter-spacing: -0.01em; }
h3 { margin: 0; font-size: 16px; }
p { margin: 0 0 10px; }
code { font-family: ui-monospace, "Cascadia Mono", "Consolas", monospace; font-size: .92em; }
.root { color: var(--muted); overflow-wrap: anywhere; }
.lede { max-width: 820px; margin-top: 14px; }
.warn { color: var(--medium); max-width: 820px; }
.muted { color: var(--muted); }
section { margin: 34px 0; }
.section-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; margin-bottom: 12px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.stat { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; }
.stat .k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
.stat .v { font-size: 22px; font-weight: 650; margin-top: 4px; }
.recs { display: grid; gap: 12px; }
.rec { background: var(--panel); border: 1px solid var(--border); border-left: 4px solid var(--low); border-radius: var(--radius); padding: 16px 18px; }
.rec[data-confidence="medium"] { border-left-color: var(--medium); }
.rec[data-confidence="high"] { border-left-color: var(--high); }
.rec-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.rec-id { color: var(--muted); font-size: 12px; margin-left: auto; }
.rec p { margin: 8px 0 0; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; border: 1px solid var(--border); font-size: 12px; color: var(--muted); background: var(--panel-2); }
.badge.high { color: var(--high); }
.badge.medium { color: var(--medium); }
.badge.low { color: var(--low); }
.meta { color: var(--muted); font-size: 13px; }
details { margin-top: 10px; }
summary { cursor: pointer; color: var(--muted); font-size: 13px; }
ul { margin: 8px 0 0; padding-left: 22px; }
li { overflow-wrap: anywhere; }
table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
tr:last-child td { border-bottom: 0; }
td.n { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.sorter { display: flex; align-items: center; gap: 8px; color: var(--muted); font-size: 13px; }
button { font: inherit; font-size: 13px; color: var(--text); background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 5px 10px; cursor: pointer; }
button.active { border-color: var(--accent); color: var(--accent); }
button:hover { border-color: var(--accent); }
.empty { color: var(--muted); font-style: italic; }
.protected { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 18px; }
.protected ul { margin: 8px 0 0; }
footer { margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--muted); font-size: 13px; }
@media (max-width: 640px) {
  main { padding: 24px 16px 56px; }
  h1 { font-size: 26px; }
  .rec-id { margin-left: 0; width: 100%; }
}
</style>
</head>
<body>
<main>
<header>
  <p class="eyebrow">Scoria · read-only disk scan</p>
  <h1>Storage review</h1>
  <p class="root"><code>{{.Root}}</code></p>
  <p class="lede">{{if .DuplicateCheck}}Scoria read metadata and verified duplicate candidates by hashing file contents. Nothing was changed or removed.{{else}}Scoria read metadata only. Nothing was changed or removed.{{end}}</p>
  {{if .Analysis}}<p class="warn">A redacted, path-free candidate payload was sent to {{.Analysis.Analyzer}}{{if .Analysis.Model}} ({{.Analysis.Model}}){{end}} for ranking and explanation. No files were changed.</p>{{end}}
  {{if .Discovery}}<p class="warn">A redacted, name-only directory summary was sent to {{.Discovery.Analyzer}}{{if .Discovery.Model}} ({{.Discovery.Model}}){{end}} to propose patterns. No files were changed.</p>{{end}}
  <p class="warn">Every recommendation is a review candidate, not a deletion plan. Verify before acting.</p>
</header>

<section>
  <div class="stats">
    <div class="stat"><div class="k">Entries</div><div class="v">{{num .Totals.Entries}}</div></div>
    <div class="stat"><div class="k">Unique files</div><div class="v">{{if .Scan.CountLinks}}{{num .Totals.UniqueFiles}}{{else}}not computed{{end}}</div></div>
    <div class="stat"><div class="k">Files</div><div class="v">{{num .Totals.Files}}</div></div>
    <div class="stat"><div class="k">Directories</div><div class="v">{{num .Totals.Directories}}</div></div>
    <div class="stat"><div class="k">Logical size</div><div class="v">{{bytes .Totals.LogicalBytes}}</div></div>
    <div class="stat"><div class="k">Unique size</div><div class="v">{{if .Scan.CountLinks}}{{bytes .Totals.UniqueBytes}}{{else}}not computed{{end}}</div></div>
    <div class="stat"><div class="k">Empty files</div><div class="v">{{num .Totals.EmptyFiles}}</div></div>
    <div class="stat"><div class="k">Elapsed</div><div class="v">{{duration .Scan.ElapsedMS}}</div></div>
  </div>
  <p class="muted" style="margin-top:12px">Scanned with {{.Scan.Workers}} directory workers at {{rate .Scan.EntriesPerSecond}} entries/sec. Sort order: {{.Scan.Sort}}.</p>
</section>

<section>
  <div class="section-head">
    <div>
      <h2>Recommendations</h2>
      <p class="muted">Rules only. {{if .DuplicateCheck}}Metadata plus duplicate hashing.{{else}}Metadata only.{{end}}</p>
    </div>
    {{if .Recommendations}}
    <div class="sorter">
      <span>Sort:</span>
      <button type="button" data-sort="priority" class="{{if eq .Scan.Sort "priority"}}active{{end}}">Priority</button>
      <button type="button" data-sort="size" class="{{if eq .Scan.Sort "size"}}active{{end}}">Size</button>
    </div>
    {{end}}
  </div>
  {{if .Recommendations}}
  <div class="recs" id="recs">
    {{range .Recommendations}}
    <article class="rec" data-confidence="{{.Confidence}}" data-priority="{{.Priority}}" data-bytes="{{.Bytes}}" data-title="{{.Title}}">
      <div class="rec-head">
        <span class="badge {{.Confidence}}">{{.Confidence}}</span>
        <h3>{{.Title}}</h3>
        <span class="rec-id">{{.ID}} · {{.Rule}}</span>
      </div>
      <p>{{.Detail}}</p>
      <p class="meta">{{num .Items}} items · {{bytes .Bytes}}</p>
      {{if .Examples}}
      <details>
        <summary>Example paths (may reveal personal data)</summary>
        <ul>{{range .Examples}}<li><code>{{.}}</code></li>{{end}}</ul>
      </details>
      {{end}}
    </article>
    {{end}}
  </div>
  {{else}}
  <p class="empty">No recommendations. That is a valid result, not a failure.</p>
  {{end}}
</section>

{{if .Analysis}}
<section>
  <h2>Cloud analysis</h2>
  <p class="muted">{{.Analysis.Analyzer}}{{if .Analysis.Model}} · {{.Analysis.Model}}{{end}}</p>
  <table>
    <thead><tr><th class="n">Rank</th><th>Candidate</th><th>Explanation</th></tr></thead>
    <tbody>{{range .Analysis.Findings}}<tr><td class="n">{{.Rank}}</td><td><code>{{.ID}}</code> {{.Title}}</td><td>{{.Explanation}}</td></tr>{{end}}</tbody>
  </table>
</section>
{{end}}

{{if .Discovery}}
<section>
  <h2>Suggested directory patterns</h2>
  <p class="muted">{{.Discovery.Analyzer}}{{if .Discovery.Model}} · {{.Discovery.Model}}{{end}}</p>
  <table>
    <thead><tr><th>Name</th><th class="n">Files</th><th class="n">Size</th><th>Confidence</th><th>Reason</th></tr></thead>
    <tbody>{{range .Discovery.Patterns}}<tr><td><code>{{.Name}}</code></td><td class="n">{{num .Files}}</td><td class="n">{{bytes .Bytes}}</td><td><span class="badge {{.Confidence}}">{{.Confidence}}</span></td><td>{{.Reason}}</td></tr>{{end}}</tbody>
  </table>
  <p class="note">These are pattern suggestions, not built-in recommendations. Review before adding them as exclusions or rules.</p>
</section>
{{end}}

{{if .DuplicateCheck}}
<section>
  <h2>Duplicate verification</h2>
  <table>
    <tbody>
      <tr><th>Candidates</th><td class="n">{{num .DuplicateCheck.Candidates}}</td></tr>
      <tr><th>Files fully hashed</th><td class="n">{{num .DuplicateCheck.Hashed}}</td></tr>
      <tr><th>Bytes read</th><td class="n">{{bytes .DuplicateCheck.BytesRead}}</td></tr>
      <tr><th>Read errors</th><td class="n">{{num .DuplicateCheck.ReadErrors}}</td></tr>
      <tr><th>Skipped protected paths</th><td class="n">{{num .DuplicateCheck.SkippedProtected}}</td></tr>
      <tr><th>Skipped hard-link entries</th><td class="n">{{num .DuplicateCheck.SkippedHardlinks}}</td></tr>
    </tbody>
  </table>
</section>
{{end}}

<section>
  <h2>Extensions</h2>
  {{if .Extensions}}
  <table>
    <thead><tr><th>Extension</th><th class="n">Files</th><th class="n">Size</th></tr></thead>
    <tbody>{{range .Extensions}}<tr><td><code>{{ext .Ext}}</code></td><td class="n">{{num .Files}}</td><td class="n">{{bytes .Bytes}}</td></tr>{{end}}</tbody>
  </table>
  {{else}}
  <p class="empty">No files were aggregated.</p>
  {{end}}
</section>

<section>
  <h2>Largest files</h2>
  {{if .Largest}}
  <table>
    <thead><tr><th>Path</th><th class="n">Size</th></tr></thead>
    <tbody>{{range .Largest}}<tr><td><code>{{.Path}}</code></td><td class="n">{{bytes .Size}}</td></tr>{{end}}</tbody>
  </table>
  {{else}}
  <p class="empty">None retained.</p>
  {{end}}
</section>

<section>
  <h2>Oldest files by last write</h2>
  {{if .Stalest}}
  <table>
    <thead><tr><th>Path</th><th class="n">Last write</th><th class="n">Size</th></tr></thead>
    <tbody>{{range .Stalest}}<tr><td><code>{{.Path}}</code></td><td class="n">{{date .ModTime}}</td><td class="n">{{bytes .Size}}</td></tr>{{end}}</tbody>
  </table>
  {{else}}
  <p class="empty">None retained.</p>
  {{end}}
</section>

<section>
  <h2>Largest directories (direct contents)</h2>
  {{if .Directories}}
  <table>
    <thead><tr><th>Path</th><th class="n">Files</th><th class="n">Size</th></tr></thead>
    <tbody>{{range .Directories}}<tr><td><code>{{.Path}}</code></td><td class="n">{{num .Files}}</td><td class="n">{{bytes .Bytes}}</td></tr>{{end}}</tbody>
  </table>
  {{else}}
  <p class="empty">None retained.</p>
  {{end}}
</section>

<section>
  <h2>Excluded by your rules</h2>
  <p class="muted">These paths were filtered at enumeration time. They are not in the totals above, the recommendations, or the digest.</p>
  {{if .Excluded}}
  <table>
    <thead><tr><th>Rule</th><th>Kind</th><th class="n">Files</th><th class="n">Dirs</th><th class="n">Size</th></tr></thead>
    <tbody>{{range .Excluded}}<tr><td><code>{{.Rule}}</code>{{if .Sensitive}} <span class="badge">sensitive</span>{{end}}</td><td>{{.Kind}}</td><td class="n">{{num .Files}}</td><td class="n">{{num .Dirs}}</td><td class="n">{{bytes .Bytes}}</td></tr>{{end}}</tbody>
  </table>
  {{else}}
  <p class="empty">No exclusion rules matched.</p>
  {{end}}
</section>

<section>
  <h2>What Scoria did not look at</h2>
  <table>
    <tbody>
      <tr><th>Reparse points skipped</th><td class="n">{{num .Skipped.ReparsePoints}} ({{num .Skipped.ReparsePointDirs}} dirs, {{num .Skipped.ReparsePointFiles}} files)</td></tr>
      <tr><th>Permission denied</th><td class="n">{{num .Skipped.PermissionDeniedDirs}} directories, {{num .Skipped.FileAccessDenied}} files</td></tr>
      <tr><th>Cloud placeholders not opened</th><td class="n">{{num .Skipped.CloudPlaceholders}} ({{bytes .Skipped.CloudPlaceholderBytes}})</td></tr>
      <tr><th>Long path names</th><td class="n">{{num .Skipped.LongPathNames}}</td></tr>
      <tr><th>Other errors</th><td class="n">{{num .Skipped.OtherErrors}} directories, {{num .Skipped.FileOpenErrors}} file opens</td></tr>
    </tbody>
  </table>
</section>

<section>
  <h2>Protected paths</h2>
  <div class="protected">
    <p>The rules layer does not recommend anything under these locations, regardless of size or age.</p>
    <ul>
      <li><code>C:\Windows</code> including WinSxS and System32 - use DISM or Windows tools</li>
      <li><code>C:\Program Files</code> and <code>C:\Program Files (x86)</code></li>
      <li><code>pagefile.sys</code>, <code>hiberfil.sys</code>, <code>swapfile.sys</code></li>
      <li><code>System Volume Information</code> - restore points and VSS</li>
      <li><code>$Recycle.Bin</code> - let Windows empty it</li>
      <li><code>C:\Recovery</code> and <code>Windows.old</code></li>
    </ul>
  </div>
</section>

<footer>
  <p>Generated {{datetime .GeneratedAt}} by Scoria. Report format v{{.Version}}.</p>
  <p>No telemetry. No network access. Nothing was deleted, moved, or renamed.</p>
</footer>
</main>
<script>
(() => {
  const list = document.getElementById('recs');
  if (!list) return;
  const cards = Array.from(list.querySelectorAll('.rec'));
  const buttons = Array.from(document.querySelectorAll('[data-sort]'));
  const order = (key) => {
    cards.sort((a, b) => {
      if (key === 'size') {
        const size = Number(b.dataset.bytes) - Number(a.dataset.bytes);
        if (size) return size;
        return Number(b.dataset.priority) - Number(a.dataset.priority);
      }
      const priority = Number(b.dataset.priority) - Number(a.dataset.priority);
      if (priority) return priority;
      return Number(b.dataset.bytes) - Number(a.dataset.bytes);
    });
    cards.forEach((card) => list.appendChild(card));
    buttons.forEach((button) => button.classList.toggle('active', button.dataset.sort === key));
  };
  buttons.forEach((button) => button.addEventListener('click', () => order(button.dataset.sort)));
})();
</script>
</body>
</html>`
