package archive

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PackageInfo is metadata extracted from an expanded macOS installer package.
type PackageInfo struct {
	ID         string             `json:"id,omitempty"`
	Version    string             `json:"version,omitempty"`
	Location   string             `json:"location,omitempty"`
	Auth       string             `json:"auth,omitempty"`
	Scripts    PackageScripts     `json:"scripts,omitempty"`
	Payload    PackagePayload     `json:"payload,omitempty"`
	Components []PackageComponent `json:"components,omitempty"`
	Signature  SignatureInfo      `json:"signature,omitempty"`
}

type PackageScripts struct {
	Preinstall  string `json:"preinstall,omitempty"`
	Postinstall string `json:"postinstall,omitempty"`
}

type PackagePayload struct {
	Size  int64 `json:"size,omitempty"`
	Items int64 `json:"items,omitempty"`
}

type PackageComponent struct {
	ID       string `json:"id,omitempty"`
	Version  string `json:"version,omitempty"`
	Location string `json:"location,omitempty"`
	Auth     string `json:"auth,omitempty"`
	Path     string `json:"path,omitempty"`
}

// ErrCheckSignature is returned when pkgutil signature output cannot be parsed.
var ErrCheckSignature = errors.New("check signature failed")

type SignatureInfo struct {
	Notarized bool      `json:"notarized"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Content   string    `json:"content,omitempty"`
	Status    string    `json:"status,omitempty"`
}

type distribution struct {
	PkgRefs []struct {
		ID string `xml:"id,attr"`
	} `xml:"pkg-ref"`
}

type pkgInfo struct {
	XMLName         xml.Name `xml:"pkg-info"`
	Identifier      string   `xml:"identifier,attr"`
	Version         string   `xml:"version,attr"`
	InstallLocation string   `xml:"install-location,attr"`
	Auth            string   `xml:"auth,attr"`
	Payload         struct {
		InstallKBytes string `xml:"installKBytes,attr"`
		NumberOfFiles string `xml:"numberOfFiles,attr"`
	} `xml:"payload"`
	Scripts struct {
		Preinstall struct {
			File string `xml:"file,attr"`
		} `xml:"preinstall"`
		Postinstall struct {
			File string `xml:"file,attr"`
		} `xml:"postinstall"`
	} `xml:"scripts"`
}

// ExtractPKG expands a .pkg with pkgutil and returns structured metadata.
// outdir must not exist beforehand (pkgutil --expand-full requirement); the
// parent directory is created if needed, and a leftover outdir is removed.
func ExtractPKG(pkgPath, outdir string) (PackageInfo, error) {
	if err := os.MkdirAll(filepath.Dir(outdir), 0o750); err != nil {
		return PackageInfo{}, err
	}
	_ = os.RemoveAll(outdir)

	cmd := exec.Command("pkgutil", "--expand-full", pkgPath, outdir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return PackageInfo{}, fmt.Errorf("pkgutil --expand-full: %w: %s", err, strings.TrimSpace(string(out)))
	}

	components, primary, err := discoverPackageComponents(outdir)
	if err != nil {
		return PackageInfo{}, err
	}

	info, pkgFile, err := readPackageInfo(primary)
	if err != nil {
		return PackageInfo{}, err
	}

	p := PackageInfo{
		ID:         info.Identifier,
		Version:    info.Version,
		Location:   info.InstallLocation,
		Auth:       info.Auth,
		Components: components,
		Scripts: PackageScripts{
			Preinstall:  readScript(pkgFile, info.Scripts.Preinstall.File),
			Postinstall: readScript(pkgFile, info.Scripts.Postinstall.File),
		},
	}
	if n, err := strconv.ParseInt(info.Payload.InstallKBytes, 10, 64); err == nil {
		p.Payload.Size = n
	}
	if n, err := strconv.ParseInt(info.Payload.NumberOfFiles, 10, 64); err == nil {
		p.Payload.Items = n
	}

	p.Signature = checkPackageSignature(pkgPath)
	return p, nil
}

func discoverPackageComponents(outdir string) ([]PackageComponent, string, error) {
	if components, primary, ok := componentsFromDistribution(outdir); ok {
		return components, primary, nil
	}

	// Flat package: PackageInfo at expand root.
	if _, err := os.Stat(filepath.Join(outdir, "PackageInfo")); err == nil {
		return []PackageComponent{{Path: outdir}}, outdir, nil
	}

	// Fallback: first nested *.pkg directory.
	entries, err := os.ReadDir(outdir)
	if err != nil {
		return nil, "", err
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".pkg") {
			path := filepath.Join(outdir, e.Name())
			return []PackageComponent{{Path: path, ID: e.Name()}}, path, nil
		}
	}
	return nil, "", fmt.Errorf("no package component found under %s", outdir)
}

func componentsFromDistribution(outdir string) ([]PackageComponent, string, bool) {
	f, err := os.Open(filepath.Join(outdir, "Distribution"))
	if err != nil {
		return nil, "", false
	}
	defer f.Close()

	var d distribution
	if err := xml.NewDecoder(f).Decode(&d); err != nil || len(d.PkgRefs) == 0 {
		return nil, "", false
	}

	seen := make(map[string]struct{}, len(d.PkgRefs))
	components := make([]PackageComponent, 0, len(d.PkgRefs))
	var primary string

	for _, ref := range d.PkgRefs {
		id := strings.TrimSpace(ref.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}

		pkgFile := resolveComponentPath(outdir, id)
		if pkgFile == "" {
			continue
		}

		comp := PackageComponent{Path: pkgFile, ID: id}
		if info, _, err := readPackageInfo(pkgFile); err == nil {
			comp.ID = firstNonEmpty(info.Identifier, id)
			comp.Version = info.Version
			comp.Location = info.InstallLocation
			comp.Auth = info.Auth
		}
		components = append(components, comp)
		if primary == "" {
			primary = pkgFile
		}
	}
	if primary == "" {
		return nil, "", false
	}
	return components, primary, true
}

func resolveComponentPath(outdir, id string) string {
	candidates := []string{
		filepath.Join(outdir, id),
		filepath.Join(outdir, id+".pkg"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}

func readPackageInfo(pkgFile string) (*pkgInfo, string, error) {
	f, err := os.Open(filepath.Join(pkgFile, "PackageInfo"))
	if err != nil {
		return nil, pkgFile, err
	}
	defer f.Close()

	info := &pkgInfo{}
	if err := xml.NewDecoder(f).Decode(info); err != nil {
		return nil, pkgFile, err
	}
	return info, pkgFile, nil
}

func readScript(pkgFile, name string) string {
	name = strings.TrimSpace(name)
	if name == "" || filepath.IsAbs(name) {
		return ""
	}
	root := filepath.Clean(pkgFile)
	for _, c := range []string{
		filepath.Join(root, "Scripts", name),
		filepath.Join(root, name),
	} {
		c = filepath.Clean(c)
		if !pathWithinRoot(root, c) {
			continue
		}
		data, err := os.ReadFile(c)
		if err == nil {
			return string(data)
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

var (
	pkgStatusPattern       = regexp.MustCompile(`(?m)^Status:\s+(.+)$`)
	pkgNotarizationPattern = regexp.MustCompile(`(?m)^Notarization:\s+(.+)$`)
	pkgTimestampPattern    = regexp.MustCompile(`(?m)^Signed with a trusted timestamp on:\s+(.+)$`)
)

func checkPackageSignature(pkgPath string) SignatureInfo {
	out, err := exec.Command("pkgutil", "--check-signature", pkgPath).CombinedOutput()
	text := strings.TrimSpace(string(out))
	info, perr := parseSignatureInfo(text)
	if perr == nil {
		return info
	}
	// pkgutil may exit non-zero for unsigned packages; still return raw output.
	if info.Content == "" {
		info.Content = text
	}
	if info.Content == "" && err != nil {
		info.Content = err.Error()
	}
	return info
}

func parseSignatureInfo(output string) (SignatureInfo, error) {
	output = strings.TrimSpace(output)
	info := SignatureInfo{Content: output}

	matches := pkgStatusPattern.FindStringSubmatch(output)
	if len(matches) != 2 {
		return info, ErrCheckSignature
	}
	info.Status = matches[1]
	if strings.EqualFold(matches[1], "no signature") {
		return info, nil
	}

	if m := pkgNotarizationPattern.FindStringSubmatch(output); len(m) >= 2 {
		info.Notarized = m[1] == "trusted by the Apple notary service"
	}
	if m := pkgTimestampPattern.FindStringSubmatch(output); len(m) >= 2 {
		if ts, err := time.Parse("2006-01-02 15:04:05 -0700", m[1]); err == nil {
			info.Timestamp = ts
		}
	}
	return info, nil
}
