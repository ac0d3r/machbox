package appbundle

import (
	"os"
	"path/filepath"
	"sort"

	"statictool/parser/filebase"

	"howett.net/plist"
)

// Bundle Structures: https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html#//apple_ref/doc/uid/10000123i-CH101-SW1

// AppBundle holds .app metadata only. Nested Mach-O / plugins are analyzed
// via analyzer Report.Children, not embedded here.
type AppBundle struct {
	Info   BundleInfo     `json:"info"`
	Hashes *filebase.Hash `json:"hashes,omitempty"` // main executable hashes when present
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

func Parse(appPath string) (AppBundle, error) {
	info, err := parseInfoPlist(appPath)
	if err != nil {
		return AppBundle{}, err
	}

	app := AppBundle{Info: info}
	if mpath := info.MainExecutablePath(appPath); mpath != "" {
		if h, err := filebase.HashFile(mpath); err == nil {
			app.Hashes = &h
		}
	}
	return app, nil
}

func parseInfoPlist(bundlePath string) (BundleInfo, error) {
	f, err := os.Open(filepath.Join(bundlePath, "Contents", "Info.plist"))
	if err != nil {
		return BundleInfo{}, err
	}
	defer f.Close()

	var info BundleInfo
	if err := plist.NewDecoder(f).Decode(&info); err != nil {
		return BundleInfo{}, err
	}

	supportedPlatforms := append([]string(nil), info.SupportedPlatforms...)
	if len(supportedPlatforms) == 0 {
		supportedPlatforms = nil
	} else {
		sort.Strings(supportedPlatforms)
	}
	info.SupportedPlatforms = supportedPlatforms
	info.MinimumSystemVersion = firstNonEmpty(info.LSMinimumSystemVersion, info.MinimumOSVersion)
	return info, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
