package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/db"

	"github.com/tidwall/gjson"
)

const sanitizedPath = "$$WORKDIR"

var workdirRegex = regexp.MustCompile(`(?:/private)?/tmp/machbox_[^/"]+`)

type Parser struct {
	data *db.Report

	pickTyp  string
	pickPath string
}

func New(env agent.GuestInfo) *Parser {
	return &Parser{data: &db.Report{AnalysisEnv: env}}
}

// GetPickFile returns the guest path of the primary executable for dynamic
// analysis, and its type (mach-o, appbundle, dylib, …).
func (p *Parser) GetPickFile() (path, typ string) {
	return p.pickPath, p.pickTyp
}

// SetPickFile updates the guest path used for dynamic analysis / report parsing.
func (p *Parser) SetPickFile(path string) {
	p.pickPath = path
}

func (p *Parser) StaticResult(data, originSample string) error {
	gjret := gjson.Parse(data)

	p.data.SHA256 = gjret.Get("base.hash.sha256").String()
	p.data.SampleName = gjret.Get("base.name").String()
	p.data.FileType = gjret.Get("base.type").String()
	p.data.FileSize = gjret.Get("base.size").Int()

	switch p.data.FileType {
	case "mach-o", "appbundle", "dylib":
		p.pickTyp = p.data.FileType
		p.pickPath = originSample
	default:
		// zip/dmg/pkg (and other containers): children carry absolute guest paths
		// under --extract-dir (writable workdir).
		path, typ := pickMainFile(&gjret)
		p.pickPath, p.pickTyp = path, typ
	}

	sanitized := workdirRegex.ReplaceAllString(data, sanitizedPath)

	var m map[string]any
	if err := json.Unmarshal([]byte(sanitized), &m); err != nil {
		return fmt.Errorf("unmarshal static report: %w", err)
	}

	p.data.StaticResult = m
	return nil
}

func (p *Parser) ParseDynamicResult(reader io.Reader) error {
	tree, parseErrors, err := parseAndBuildTree(reader, p.pickPath)
	if err != nil {
		p.data.Error = fmt.Sprintf("dynamic parse failed: %v", err)
		return fmt.Errorf("parse dynamic result: %w", err)
	}

	summary := summarize(tree, parseErrors)

	p.data.DynamicResult = &DynamicReport{
		ProcessTree: tree,
		Summary:     summary,
	}
	p.data.Verdict = summary.Verdict
	return nil
}

func (p *Parser) Save() error {
	return db.CreateReport(p.data)
}

type pickCandidate struct {
	path string
	typ  string
}

func pickMainFile(gjret *gjson.Result) (path, typ string) {
	var apps, machosOutside, machosInside []pickCandidate

	var walk func(gjson.Result)
	walk = func(r gjson.Result) {
		if !r.IsArray() {
			return
		}
		r.ForEach(func(_, item gjson.Result) bool {
			typ := item.Get("base.type").String()
			path := strings.TrimSpace(item.Get("base.path").String())
			if path != "" {
				switch typ {
				case "appbundle":
					// Skip Helper.app nested under another .app.
					if !isNestedAppBundle(path) {
						apps = append(apps, pickCandidate{path: path, typ: typ})
					}
				case "mach-o":
					c := pickCandidate{path: path, typ: typ}
					if pathInsideAppBundle(path) {
						machosInside = append(machosInside, c)
					} else {
						machosOutside = append(machosOutside, c)
					}
					// dylib intentionally omitted — not a useful dynamic launch target.
				}
			}
			walk(item.Get("children"))
			return true
		})
	}
	walk(gjret.Get("children"))

	stem := archiveStem(gjret.Get("base.name").String())
	switch {
	case len(apps) > 0:
		return bestPickCandidate(apps, stem)
	case len(machosOutside) > 0:
		return bestPickCandidate(machosOutside, stem)
	case len(machosInside) > 0:
		return bestPickCandidate(machosInside, stem)
	default:
		return "", ""
	}
}

func bestPickCandidate(cs []pickCandidate, stem string) (path, typ string) {
	sort.Slice(cs, func(i, j int) bool {
		ni := nameMatchRank(cs[i].path, stem)
		nj := nameMatchRank(cs[j].path, stem)
		if ni != nj {
			return ni < nj
		}
		di := pathDepth(cs[i].path)
		dj := pathDepth(cs[j].path)
		if di != dj {
			return di < dj
		}
		return cs[i].path < cs[j].path
	})
	return cs[0].path, cs[0].typ
}

func archiveStem(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." {
		return ""
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	// sample.tar.gz-style: strip one more known archive suffix if present.
	switch strings.ToLower(filepath.Ext(stem)) {
	case ".tar":
		stem = strings.TrimSuffix(stem, filepath.Ext(stem))
	}
	return stem
}

// nameMatchRank: lower is better (exact = 0, partial = 1, none = 2).
func nameMatchRank(path, stem string) int {
	if stem == "" {
		return 1
	}
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	bl := strings.ToLower(base)
	sl := strings.ToLower(stem)
	switch {
	case bl == sl:
		return 0
	case strings.Contains(bl, sl) || strings.Contains(sl, bl):
		return 1
	default:
		return 2
	}
}

func pathDepth(path string) int {
	clean := filepath.Clean(path)
	if clean == "" || clean == "." || clean == string(filepath.Separator) {
		return 0
	}
	return strings.Count(clean, string(filepath.Separator))
}

func isNestedAppBundle(path string) bool {
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	n := 0
	for _, part := range parts {
		if strings.HasSuffix(strings.ToLower(part), ".app") {
			n++
		}
	}
	return n > 1
}

func pathInsideAppBundle(path string) bool {
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts[:len(parts)-1] {
		if strings.HasSuffix(strings.ToLower(part), ".app") {
			return true
		}
	}
	return false
}
