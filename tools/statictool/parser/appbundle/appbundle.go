package appbundle

import (
	"os"
	"path/filepath"
	"sort"

	"statictool/parser/filebase"
	"statictool/parser/macho"

	"howett.net/plist"
)

// Bundle Structures: https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html#//apple_ref/doc/uid/10000123i-CH101-SW1

type AppBundle struct {
	Info           BundleInfo     `json:"info"`
	MainExecutable *Executable    `json:"main_executable,omitempty"`
	Hashes         *filebase.Hash `json:"hashes,omitempty"`
}

type BundleInfo struct {
	Identifier  string `json:"identifier,omitempty" plist:"CFBundleIdentifier"`
	Name        string `json:"name,omitempty" plist:"CFBundleName"`
	DisplayName string `json:"display_name,omitempty" plist:"CFBundleDisplayName"`
	Executable  string `json:"executable,omitempty" plist:"CFBundleExecutable"`
	Version     string `json:"version,omitempty" plist:"CFBundleShortVersionString"`
	Build       string `json:"build,omitempty" plist:"CFBundleVersion"`
	PackageType string `json:"package_type,omitempty" plist:"CFBundlePackageType"`

	LSMinimumSystemVersion string `json:"-" plist:"LSMinimumSystemVersion"`
	MinimumOSVersion       string `json:"-" plist:"MinimumOSVersion"`
	MinimumSystemVersion   string `json:"minimum_system_version,omitempty"`

	SupportedPlatforms []string `json:"supported_platforms,omitempty" plist:"CFBundleSupportedPlatforms"`
}

func (i BundleInfo) MainExecutablePath(bundlePath string) string {
	if i.Executable == "" {
		return ""
	}
	return filepath.Join(bundlePath, "Contents", "MacOS", i.Executable)
}

type Executable struct {
	RelativePath string          `json:"relative_path,omitempty"`
	MachO        macho.MachoFile `json:"macho,omitempty"`
}

func Parse(appPath string) (app AppBundle, err error) {
	app.Info, err = parseInfoPlist(appPath)
	if err != nil {
		return app, err
	}

	if mpath := app.Info.MainExecutablePath(appPath); mpath != "" {
		app.MainExecutable, err = parseExecutable(mpath, appPath)
		if err != nil {
			return
		}
		if h, err := filebase.HashFile(mpath); err == nil {
			app.Hashes = &h
		}
	}

	return
}

func parseInfoPlist(bundlePath string) (info BundleInfo, err error) {
	f, err := os.Open(filepath.Join(bundlePath, "Contents", "Info.plist"))
	if err != nil {
		return
	}
	defer f.Close()

	if err := plist.NewDecoder(f).Decode(&info); err != nil {
		return BundleInfo{}, err
	}

	supportedPlatforms := append([]string(nil), info.SupportedPlatforms...)
	if len(supportedPlatforms) == 0 {
		supportedPlatforms = nil
	} else {
		sort.Strings(supportedPlatforms)
	}

	info.MinimumSystemVersion = firstNonEmpty(info.LSMinimumSystemVersion, info.MinimumOSVersion)
	return info, nil
}

func parseExecutable(path, basePath string) (*Executable, error) {
	info, err := macho.Parse(path)
	if err != nil {
		return nil, err
	}

	return &Executable{
		RelativePath: relativePath(basePath, path),
		MachO:        info,
	}, nil
}

func isBundleDirectory(path string) bool {
	infoPlist := filepath.Join(path, "Contents", "Info.plist")
	if _, err := os.Stat(infoPlist); err != nil {
		return false
	}
	return true
}

func relativePath(basePath, targetPath string) string {
	relPath, err := filepath.Rel(basePath, targetPath)
	if err != nil {
		return targetPath
	}
	return relPath
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
