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

type PackageInfo struct {
	ID       string `json:"id,omitempty"`
	Version  string `json:"version,omitempty"`
	Location string `json:"location,omitempty"`
	Auth     string `json:"auth,omitempty"`
	Scripts  struct {
		Preinstall  string `json:"preinstall,omitempty"`
		Postinstall string `json:"postinstall,omitempty"`
	} `json:"scripts,omitempty"`
	Payload struct {
		Size         int64     `json:"size,omitempty"`
		Items        int64     `json:"items,omitempty"`
		Tree         *FileNode `json:"tree,omitempty"`
		ExpandedPath string    `json:"expanded_path,omitempty"`
	} `json:"payload,omitempty"`
	Components []PackageComponent `json:"components,omitempty"`
	Signature  SignatureInfo      `json:"signature"`
}

type PackageComponent struct {
	ID       string `json:"id,omitempty"`
	Version  string `json:"version,omitempty"`
	Location string `json:"location,omitempty"`
	Auth     string `json:"auth,omitempty"`
	Path     string `json:"path,omitempty"`
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

// Extract expands a .pkg with pkgutil and returns structured metadata.
// outdir is the expand destination (created by the caller).
func Extract(pkgPath, outdir string) (p PackageInfo, err error) {
	if err := exec.Command("pkgutil", "--expand-full", pkgPath, outdir).Run(); err != nil {
		return p, fmt.Errorf("pkgutil --expand-full: %w", err)
	}

	components, primary, err := discoverPackageComponents(outdir)
	if err != nil {
		return p, err
	}
	p.Components = components

	pkginfo, pkgFile, err := readPackageInfo(primary)
	if err != nil {
		return p, err
	}

	p.ID = pkginfo.Identifier
	p.Version = pkginfo.Version
	p.Location = pkginfo.InstallLocation
	p.Auth = pkginfo.Auth

	p.Scripts.Preinstall = readScript(pkgFile, pkginfo.Scripts.Preinstall.File)
	p.Scripts.Postinstall = readScript(pkgFile, pkginfo.Scripts.Postinstall.File)

	if num, err := strconv.Atoi(pkginfo.Payload.InstallKBytes); err == nil {
		p.Payload.Size = int64(num)
	}
	if num, err := strconv.Atoi(pkginfo.Payload.NumberOfFiles); err == nil {
		p.Payload.Items = int64(num)
	}

	payloadPath := filepath.Join(pkgFile, "Payload")
	if st, err := os.Stat(payloadPath); err == nil && st.IsDir() {
		p.Payload.ExpandedPath = payloadPath
		node, err := buildPkgPayload(p.Location, payloadPath)
		if err != nil {
			return p, err
		}
		p.Payload.Tree = node
	}

	output, sigErr := exec.Command("pkgutil", "--check-signature", pkgPath).CombinedOutput()
	p.Signature, err = parseSignatureInfo(string(output))
	if err != nil && !errors.Is(err, ErrCheckSignature) {
		return p, err
	}
	if sigErr != nil && p.Signature.Content == "" {
		p.Signature.Content = strings.TrimSpace(string(output))
		if p.Signature.Content == "" {
			p.Signature.Content = sigErr.Error()
		}
	}
	return p, nil
}

func discoverPackageComponents(outdir string) ([]PackageComponent, string, error) {
	// Prefer Distribution pkg-ref list when present.
	distPath := filepath.Join(outdir, "Distribution")
	if f, err := os.Open(distPath); err == nil {
		defer f.Close()
		d := &distribution{}
		if err := xml.NewDecoder(f).Decode(d); err == nil && len(d.PkgRefs) > 0 {
			seen := make(map[string]struct{})
			var components []PackageComponent
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
				info, _, err := readPackageInfo(pkgFile)
				comp := PackageComponent{Path: pkgFile, ID: id}
				if err == nil {
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
			if primary != "" {
				return components, primary, nil
			}
		}
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

func resolveComponentPath(outdir, id string) string {
	candidates := []string{
		filepath.Join(outdir, id),
		filepath.Join(outdir, id+".pkg"),
	}
	if !strings.HasSuffix(id, ".pkg") {
		candidates = append(candidates, filepath.Join(outdir, id+".pkg"))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}

func readPackageInfo(pkgFile string) (*pkgInfo, string, error) {
	path := filepath.Join(pkgFile, "PackageInfo")
	f, err := os.Open(path)
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
	if name == "" {
		return ""
	}
	candidates := []string{
		filepath.Join(pkgFile, "Scripts", name),
		filepath.Join(pkgFile, name),
	}
	for _, c := range candidates {
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

var ErrCheckSignature = errors.New("check signature failed")

type SignatureInfo struct {
	Notarized bool      `json:"notarized"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Content   string    `json:"content,omitempty"`
	Status    string    `json:"status,omitempty"`
}

var (
	statusPattern       = regexp.MustCompile(`Status:\s+(.+)`)
	notarizationPattern = regexp.MustCompile(`Notarization:\s+(.+)`)
	timestampPattern    = regexp.MustCompile(`Signed with a trusted timestamp on:\s+(.+)`)
)

func parseSignatureInfo(output string) (info SignatureInfo, err error) {
	output = strings.TrimSpace(output)
	info.Content = output
	matches := statusPattern.FindStringSubmatch(output)
	if len(matches) != 2 {
		return info, ErrCheckSignature
	}
	info.Status = matches[1]
	if strings.EqualFold(matches[1], "no signature") {
		return info, nil
	}

	if matches := notarizationPattern.FindStringSubmatch(output); len(matches) >= 2 {
		info.Notarized = matches[1] == "trusted by the Apple notary service"
	}

	if matches := timestampPattern.FindStringSubmatch(output); len(matches) >= 2 {
		if timestamp, err := time.Parse("2006-01-02 15:04:05 -0700", matches[1]); err == nil {
			info.Timestamp = timestamp
		}
	}
	return info, nil
}

type FileNode struct {
	Name     string      `json:"name"`
	IsDir    bool        `json:"isdir"`
	Children []*FileNode `json:"children,omitempty"`
}

func buildPkgPayload(location, root string) (*FileNode, error) {
	node, err := buildFileTree(root)
	if err != nil {
		return nil, err
	}
	if location != "" {
		node.Name = location
	}
	return node, nil
}

func buildFileTree(root string) (*FileNode, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	node := &FileNode{
		Name:  info.Name(),
		IsDir: info.IsDir(),
	}

	if info.IsDir() {
		files, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			childPath := filepath.Join(root, file.Name())
			childNode, err := buildFileTree(childPath)
			if err != nil {
				return nil, err
			}
			node.Children = append(node.Children, childNode)
		}
	}

	return node, nil
}
