package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ac0d3r/machbox/core/vsock/protocol"

	"github.com/tidwall/gjson"
)

const sanitizedPath = "$$WORKDIR"

var workdirRegex = regexp.MustCompile(`(?:/private)?/tmp/machbox_[^/"]+`)

type Parser struct {
	data *Report

	pickTyp       string
	pickeFile     string
	pickeFilePath string
}

func New(env protocol.GuestInfo) *Parser {
	return &Parser{data: &Report{AnalysisEnv: env}}
}

func (p *Parser) GetPickeFile() (path, typ string) {
	return p.pickeFile, p.pickTyp
}

func (p *Parser) StaticResult(data, originSample, workpath string) error {
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
		p.pickeFile, p.pickTyp = pickMainFile(&gjret)
		if p.pickeFile != "" {
			p.pickeFilePath = filepath.Join(workpath, p.pickeFile)
		}
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
	return CreateReport(p.data)
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

	rel := strings.TrimSpace(candidates[0].path)
	rel = strings.TrimPrefix(rel, string(filepath.Separator))
	return rel, candidates[0].typ
}
