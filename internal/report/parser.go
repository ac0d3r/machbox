package report

import (
	"encoding/json"
	"fmt"
	"io"
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

	pickTyp       string
	pickeFile     string
	pickeFilePath string
}

func New(env agent.GuestInfo) *Parser {
	return &Parser{data: &db.Report{AnalysisEnv: env}}
}

// GetPickFile returns the guest path of the primary executable for dynamic
// analysis, and its type (mach-o, appbundle, dylib, …).
func (p *Parser) GetPickFile() (path, typ string) {
	return p.pickeFilePath, p.pickTyp
}

// SetPickFile updates the guest path used for dynamic analysis / report parsing.
func (p *Parser) SetPickFile(path string) {
	p.pickeFilePath = path
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
		p.pickeFile, p.pickeFilePath = originSample, originSample
	default:
		// zip/dmg/pkg (and other containers): children carry absolute guest paths
		// under --extract-dir (writable workdir).
		path, typ := pickMainFile(&gjret)
		p.pickeFile, p.pickTyp = path, typ
		p.pickeFilePath = path
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
	tree, parseErrors, err := parseAndBuildTree(reader, p.pickeFilePath)
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

func pickMainFile(gjret *gjson.Result) (path, typ string) {
	type candidate struct {
		path string
		typ  string
	}
	var candidates []candidate

	var walk func(gjson.Result)
	walk = func(r gjson.Result) {
		if !r.IsArray() {
			return
		}
		r.ForEach(func(_, item gjson.Result) bool {
			typ := item.Get("base.type").String()
			path := item.Get("base.path").String()
			if path != "" && (typ == "mach-o" || typ == "appbundle" || typ == "dylib") {
				candidates = append(candidates, candidate{path: path, typ: typ})
			}
			walk(item.Get("children"))
			return true
		})
	}
	walk(gjret.Get("children"))

	if len(candidates) == 0 {
		return "", ""
	}

	priority := map[string]int{"appbundle": 0, "mach-o": 1, "dylib": 2}
	sort.Slice(candidates, func(i, j int) bool {
		pi := priority[candidates[i].typ]
		pj := priority[candidates[j].typ]
		if pi != pj {
			return pi < pj
		}
		return candidates[i].path < candidates[j].path
	})

	return strings.TrimSpace(candidates[0].path), candidates[0].typ
}
