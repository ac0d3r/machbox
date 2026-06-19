package filebase

import (
	"os"
	"os/exec"
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
	Evidence Evidence `json:"evidence,omitempty"`
	Hash     Hash     `json:"hash"`
}

type Evidence struct {
	FileType string `json:"filetype,omitempty"`
	MIME     string `json:"mime,omitempty"`
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

	if !info.IsDir {
		if info.Hash, err = HashFile(path); err != nil {
			return info, err
		}
	}

	info.Evidence.FileType, err = detectWithFile(path)
	if err != nil {
		return info, err
	}

	mtype, err := mimetype.DetectFile(path)
	if err == nil {
		info.Evidence.MIME = mtype.String()
	}

	info.Type = detectType(path, info)
	return info, nil
}

func detectWithFile(targetPath string) (string, error) {
	output, err := exec.Command("file", "-b", targetPath).Output()
	if err != nil {
		return "", err
	}

	out := strings.TrimSpace(string(output))

	if strings.HasPrefix(out, "Mach-O universal binary") {
		if res := strings.Split(out, "\n"); len(res) > 0 {
			out = res[0]
		}
	}

	return out, nil
}

func detectType(path string, info BaseInfo) FileType {
	switch {
	case info.IsDir && info.Ext == ".app" && hasAppBundleStructure(path):
		return TypeAppBundle
	case info.Evidence.MIME == "application/zip" || strings.HasPrefix(info.Evidence.FileType, "Zip archive data"):
		return TypeZIP
	case info.Ext == ".pkg":
		return TypePKG
	case info.Ext == ".dmg":
		return TypeDMG
	case info.Evidence.MIME == "application/x-mach-binary" ||
		strings.HasPrefix(info.Evidence.FileType, "Mach-O"):

		if info.Ext == ".dylib" || strings.Contains(strings.ToLower(info.Evidence.FileType), "dynamically linked shared library") {
			return TypeDylib
		}
		return TypeMachO
	default:
		return TypeUnknown
	}
}

func hasAppBundleStructure(path string) bool {
	infoPlist := filepath.Join(path, "Contents", "Info.plist")
	if _, err := os.Stat(infoPlist); err != nil {
		return false
	}
	return true
}
