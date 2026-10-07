package filebase

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gabriel-vasile/mimetype"
)

type FileType string

const (
	TypeUnknown   FileType = "unknown"
	TypeMachO     FileType = "mach-o"
	TypeDylib     FileType = "dylib"
	TypeAppBundle FileType = "appbundle"

	// archive file
	TypeZIP FileType = "zip"
	TypePKG FileType = "pkg"
	TypeDMG FileType = "dmg"
)

type BaseInfo struct {
	FileName string   `json:"name"`
	FilePath string   `json:"path"`
	Size     int64    `json:"size"`
	IsDir    bool     `json:"is_dir,omitempty"`
	Ext      string   `json:"ext,omitempty"`
	Type     FileType `json:"type"`
	MIME     string   `json:"mime,omitempty"`
	Hash     Hash     `json:"hash,omitempty"`
}

func GenFromFile(path string) (info BaseInfo, err error) {
	info.FilePath = path
	info.FileName = filepath.Base(path)
	info.Ext = strings.ToLower(filepath.Ext(path))

	fi, err := os.Stat(path)
	if err != nil {
		return info, err
	}
	info.Size = fi.Size()
	info.IsDir = fi.IsDir()

	if info.IsDir {
		info.Type = detectType(path, info, sniffResult{})
		return info, nil
	}

	sniffed, hash, err := inspectFile(path, info.Size)
	if err != nil {
		return info, err
	}
	info.Hash = hash
	info.MIME = sniffed.MIME
	info.Type = detectType(path, info, sniffed)
	return info, nil
}

func inspectFile(path string, size int64) (sniffResult, Hash, error) {
	f, err := os.Open(path)
	if err != nil {
		return sniffResult{}, Hash{}, err
	}
	defer f.Close()

	header := make([]byte, 4096)
	n, err := f.Read(header)
	if n == 0 && err != nil && err != io.EOF {
		return sniffResult{}, Hash{}, err
	}
	header = header[:n]

	sniffed := sniffHeader(header)
	if sniffed.Kind == kindUnknown && size >= 512 {
		trailer := make([]byte, 512)
		if _, rerr := f.ReadAt(trailer, size-512); rerr == nil && sniffDMGTrailer(trailer) {
			sniffed.Kind = kindDMG
		}
	}

	if mt := mimetype.Detect(header); mt != nil {
		sniffed.MIME = mt.String()
	}

	if _, err := f.Seek(0, 0); err != nil {
		return sniffed, Hash{}, err
	}
	hash, err := hashReader(f)
	if err != nil {
		return sniffed, Hash{}, err
	}
	return sniffed, hash, nil
}

func detectType(path string, info BaseInfo, sniffed sniffResult) FileType {
	if info.IsDir && info.Ext == ".app" && hasAppBundleStructure(path) {
		return TypeAppBundle
	}

	mime := info.MIME
	if mime == "" {
		mime = sniffed.MIME
	}

	isMach := sniffed.Kind == kindMachO || sniffed.Kind == kindDylib ||
		mime == "application/x-mach-binary"
	isDylib := sniffed.Kind == kindDylib || info.Ext == ".dylib"

	// Archive types apply to files only. Expanded PKG components are directories
	// (e.g. com.example.pkg/) and must be scanned as directories, not re-expanded.
	if !info.IsDir {
		switch {
		case sniffed.Kind == kindZIP ||
			mime == "application/zip" ||
			mime == "application/x-zip-compressed" ||
			info.Ext == ".zip":
			return TypeZIP

		case sniffed.Kind == kindXAR ||
			info.Ext == ".pkg" ||
			info.Ext == ".xar" ||
			strings.Contains(mime, "xar"):
			return TypePKG

		case sniffed.Kind == kindDMG ||
			info.Ext == ".dmg" ||
			mime == "application/x-apple-diskimage":
			return TypeDMG

		case isMach && isDylib:
			return TypeDylib

		case isMach:
			return TypeMachO

		case info.Ext == ".dylib":
			return TypeDylib
		}
	}

	return TypeUnknown
}

func hasAppBundleStructure(path string) bool {
	_, err := os.Stat(filepath.Join(path, "Contents", "Info.plist"))
	return err == nil
}
