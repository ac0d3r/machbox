package statictool

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"statictool/parser/appbundle"
	"statictool/parser/archive"
	"statictool/parser/filebase"
	"statictool/parser/macho"
)

// Report is one analyzed node.
//
// Base is identity (path, type, hashes).
// Data is type-specific metadata only (no nested analysis, no directory trees).
// Children are recursively analyzed interesting nested artifacts.
type Report struct {
	Base     filebase.BaseInfo `json:"base"`
	Data     any               `json:"data,omitempty"`
	Children []Report          `json:"children,omitempty"`
}

type AnalyzeOptions struct {
	ArchivePassword string
	ExtractDir      string // required for zip/dmg/pkg; e.g. --extract-dir
}

type Analyzer struct {
	opts AnalyzeOptions
}

func NewAnalyzer(opts AnalyzeOptions) *Analyzer {
	return &Analyzer{opts: opts}
}

func Analyze(path string) (Report, error) {
	return NewAnalyzer(AnalyzeOptions{}).Analyze(path)
}

func (a *Analyzer) Analyze(path string) (Report, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Report{}, err
	}
	return a.analyzePath(absPath)
}

func (a *Analyzer) analyzePath(path string) (Report, error) {
	base, err := filebase.GenFromFile(path)
	if err != nil {
		return Report{}, err
	}

	report := Report{Base: base}
	switch base.Type {
	case filebase.TypeMachO, filebase.TypeDylib:
		report.Data, err = macho.Parse(path)
	case filebase.TypeAppBundle:
		report.Data, err = appbundle.Parse(path)
		if err != nil {
			return report, err
		}
		report.Children, err = a.scanDirectory(path)
	case filebase.TypeZIP, filebase.TypeDMG, filebase.TypePKG:
		report.Data, report.Children, err = a.analyzeArchive(path, base.Type)
	default:
		if base.IsDir {
			report.Children, err = a.scanDirectory(path)
		}
	}
	if err != nil {
		return report, err
	}
	return report, nil
}

// analyzeArchive extracts a container under ExtractDir, then scans it.
// PKG also returns package metadata as Data; ZIP/DMG leave Data nil.
func (a *Analyzer) analyzeArchive(path string, fileType filebase.FileType) (any, []Report, error) {
	if a.opts.ExtractDir == "" {
		return nil, nil, fmt.Errorf("ExtractDir is required for %s", fileType)
	}

	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if name == "" || name == "." {
		name = "extract"
	}
	if err := os.MkdirAll(a.opts.ExtractDir, 0o750); err != nil {
		return nil, nil, err
	}
	outDir := filepath.Join(a.opts.ExtractDir, name)

	var data any
	var err error
	switch fileType {
	case filebase.TypeZIP:
		err = archive.ExtractZIP(path, outDir, a.opts.ArchivePassword)
	case filebase.TypeDMG:
		err = archive.ExtractDiskImage(path, outDir)
	case filebase.TypePKG:
		// pkgutil --expand-full requires outDir to not exist yet.
		var info archive.PackageInfo
		info, err = archive.ExtractPKG(path, outDir)
		if err == nil {
			data = info
		}
	default:
		return nil, nil, fmt.Errorf("unsupported archive type %q", fileType)
	}
	if err != nil {
		return nil, nil, err
	}

	children, err := a.scanDirectory(outDir)
	return data, children, err
}

func (a *Analyzer) scanDirectory(root string) ([]Report, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	root = filepath.Clean(root)
	children := make([]Report, 0, len(entries))
	for _, entry := range entries {
		childPath := filepath.Join(root, entry.Name())
		// Do not follow symlinks (DMG often has Applications → /Applications).
		if info, err := os.Lstat(childPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
			continue
		}

		child, err := a.analyzePath(childPath)
		if err != nil {
			return nil, err
		}
		if !isInterested(child) {
			continue
		}
		children = append(children, child)
	}

	slices.SortFunc(children, func(a, b Report) int {
		return strings.Compare(a.Base.FileName, b.Base.FileName)
	})
	return children, nil
}

func isInterested(r Report) bool {
	switch r.Base.Type {
	case filebase.TypeAppBundle, filebase.TypeMachO, filebase.TypeDylib,
		filebase.TypeZIP, filebase.TypeDMG, filebase.TypePKG:
		return true
	}
	return r.Base.IsDir && len(r.Children) > 0
}
