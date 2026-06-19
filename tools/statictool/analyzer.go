package statictool

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"statictool/parser/appbundle"
	"statictool/parser/archive"
	"statictool/parser/filebase"
	"statictool/parser/macho"
)

type Report struct {
	Base     filebase.BaseInfo `json:"base"`
	Data     any               `json:"data,omitempty"`
	Children []Report          `json:"children,omitempty"`
}

type AnalyzeOptions struct {
	ArchivePassword string
	ExtractDir      string
}

type Analyzer struct {
	opts AnalyzeOptions
}

func NewAnalyzer(opts AnalyzeOptions) *Analyzer {
	return &Analyzer{opts: opts}
}

func Analyze(path string) (report Report, err error) {
	return NewAnalyzer(AnalyzeOptions{}).Analyze(path)
}

func (a *Analyzer) Analyze(path string) (report Report, err error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return
	}

	return a.analyzePath(absPath)
}

func (a *Analyzer) analyzePath(path string) (report Report, err error) {
	report.Base, err = filebase.GenFromFile(path)
	if err != nil {
		return
	}

	switch report.Base.Type {
	case filebase.TypeMachO, filebase.TypeDylib:
		report.Data, err = macho.Parse(path)
	case filebase.TypeAppBundle:
		report.Data, err = appbundle.Parse(path)
	case filebase.TypeZIP, filebase.TypeDMG:
		report.Children, err = a.analyzeArchive(path, report.Base.Type)
		if err != nil {
			return report, err
		}
	default:
		if report.Base.IsDir {
			report.Children, err = a.scanDirectory(path)
			if err != nil {
				return report, err
			}
		}
	}

	return

}

func (a *Analyzer) analyzeArchive(path string, fileType filebase.FileType) (reports []Report, err error) {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	extractDir := filepath.Join(a.opts.ExtractDir, base)
	if err := os.MkdirAll(extractDir, 0o750); err != nil {
		return nil, err
	}

	switch fileType {
	case filebase.TypeZIP:
		err = archive.ExtractZIP(path, extractDir, a.opts.ArchivePassword)
	case filebase.TypeDMG:
		err = archive.ExtractDiskImage(path, extractDir)
	default:
		err = fmt.Errorf("unsupported archive type %q", fileType)
	}

	if err != nil {
		return nil, err
	}

	return a.scanDirectory(extractDir)
}

func (a *Analyzer) scanDirectory(root string) (children []Report, err error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.Name() == "Applications" {
			continue
		}

		childPath := filepath.Join(root, entry.Name())

		report, err := a.analyzePath(childPath)
		if err != nil {
			return nil, err
		}

		if !isInterested(report.Base.Type, report.Base.IsDir, len(report.Children) > 0) {
			continue
		}

		children = append(children, report)
	}

	sort.Slice(children, func(i, j int) bool {
		return strings.Compare(children[i].Base.FileName, children[j].Base.FileName) < 0
	})

	return children, nil
}

func isInterested(t filebase.FileType, isDir bool, hasChildren bool) bool {
	if t == filebase.TypeAppBundle || t == filebase.TypeMachO || t == filebase.TypeDylib {
		return true
	}

	return isDir && hasChildren
}
