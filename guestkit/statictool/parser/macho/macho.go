package macho

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	gomacho "github.com/blacktop/go-macho"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/go-macho/types"
	"github.com/smallstep/pkcs7"
	"howett.net/plist"

	"statictool/ioc"
)

type MachoFile map[string]MachoInfo

type MachoInfo struct {
	Header        Header         `json:"header,omitempty"`
	LoadCommands  []LoadCommand  `json:"load_commands,omitempty"`
	Sections      []Section      `json:"sections,omitempty"`
	Symbol        SymbolTable    `json:"symbol,omitempty"`
	Strings       Strings        `json:"strings,omitempty"`
	CodeSignature *CodeSignature `json:"code_signature,omitempty"`
}

type Header struct {
	CPU    string `json:"cpu,omitempty"`
	SubCPU string `json:"sub_cpu,omitempty"`
	Type   string `json:"type,omitempty"`
	Flags  string `json:"flags,omitempty"`
	Ncmds  uint32 `json:"ncmds,omitempty"`
}

type LoadCommand struct {
	Command string `json:"command,omitempty"`
	Size    uint32 `json:"size,omitempty"`
	Content string `json:"content,omitempty"`
}

type Section struct {
	Name   string `json:"name"`
	Filesz uint64 `json:"filesz"`
	Memsz  uint64 `json:"memsz"`
	Offset uint64 `json:"offset"`
	Addr   uint64 `json:"addr"`
	VMprot string `json:"vmprot"`
	Flags  string `json:"flags"`
}

type SymbolTable struct {
	Locals  []Symbol            `json:"locals,omitempty"`
	Imports map[string][]string `json:"imports,omitempty"`
	Exports []Symbol            `json:"exports,omitempty"`
}

type Symbol struct {
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
	Address string `json:"address,omitempty"`
}

type Strings struct {
	CStrings []string `json:"cstrings,omitempty"`
	IOCs     []string `json:"iocs,omitempty"`
}

type CodeSignature struct {
	Signed          bool            `json:"signed"`
	Adhoc           bool            `json:"adhoc,omitempty"`
	Identifier      string          `json:"identifier,omitempty"`
	TeamID          string          `json:"team_id,omitempty"`
	CDHash          string          `json:"cdhash,omitempty"`
	Signer          string          `json:"signer,omitempty"`
	Certificates    []Certificate   `json:"certificates,omitempty"`
	Entitlements    map[string]any  `json:"entitlements,omitempty"`
	Requirements    []Requirement   `json:"requirements,omitempty"`
	CodeDirectories []CodeDirectory `json:"code_directories,omitempty"`
}

type Requirement struct {
	Type   string `json:"type,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type Certificate struct {
	Index      int    `json:"index"`
	Subject    string `json:"subject,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	CommonName string `json:"common_name,omitempty"`
	Serial     string `json:"serial,omitempty"`
	NotBefore  string `json:"not_before,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	IsSigner   bool   `json:"is_signer,omitempty"`
}

type CodeDirectory struct {
	ID               string `json:"id,omitempty"`
	TeamID           string `json:"team_id,omitempty"`
	CDHash           string `json:"cdhash,omitempty"`
	Version          string `json:"version,omitempty"`
	Flags            string `json:"flags,omitempty"`
	SpecialSlots     uint32 `json:"special_slots,omitempty"`
	CodeSlots        uint32 `json:"code_slots,omitempty"`
	HashSize         uint8  `json:"hash_size,omitempty"`
	HashType         string `json:"hash_type,omitempty"`
	Platform         string `json:"platform,omitempty"`
	CodeLimit        uint64 `json:"code_limit,omitempty"`
	RuntimeVersion   string `json:"runtime_version,omitempty"`
	ExecSegmentFlags string `json:"exec_segment_flags,omitempty"`
}

func Parse(machoPath string) (info MachoFile, err error) {
	info = make(MachoFile)

	fat, err := gomacho.OpenFat(machoPath)
	switch err {
	case nil:
		defer fat.Close()
		for _, arch := range fat.Arches {
			m, parseErr := parseMacho(arch.File)
			if parseErr != nil {
				return nil, parseErr
			}
			info[archKey(m.Header)] = m
		}
		return info, nil
	case gomacho.ErrNotFat:
		file, openErr := gomacho.Open(machoPath)
		if openErr != nil {
			return nil, openErr
		}
		defer file.Close()

		m, parseErr := parseMacho(file)
		if parseErr != nil {
			return nil, parseErr
		}
		info[archKey(m.Header)] = m
		return info, nil
	default:
		return nil, err
	}
}

func parseMacho(f *gomacho.File) (m MachoInfo, err error) {
	m.Header = Header{
		CPU:    f.FileHeader.CPU.String(),
		SubCPU: f.FileHeader.SubCPU.String(f.FileHeader.CPU),
		Type:   f.FileHeader.Type.String(),
		Flags:  f.FileHeader.Flags.String(),
		Ncmds:  f.FileHeader.NCommands,
	}

	m.LoadCommands = parseLoadCommands(f)
	m.Sections = parseSections(f)
	// Code signature parsing is best-effort; don't let a corrupted signature
	// block extraction of other metadata.
	m.CodeSignature, _ = parseCodeSignature(f)

	if err := parseSymbols(f, &m.Symbol); err != nil {
		return m, err
	}
	m.Strings = parseStrings(f)

	return m, nil
}

func archKey(h Header) string {
	if h.SubCPU == "" {
		return h.CPU
	}
	return h.CPU + "/" + h.SubCPU
}

func parseLoadCommands(f *gomacho.File) []LoadCommand {
	commands := make([]LoadCommand, 0, len(f.Loads))
	for _, load := range f.Loads {
		cmd := LoadCommand{
			Command: load.Command().String(),
			Size:    load.LoadSize(),
		}

		switch load.Command() {
		case types.LC_SEGMENT, types.LC_SEGMENT_64:
			if segment, ok := load.(*gomacho.Segment); ok {
				cmd.Content = segment.Name
			}
		default:
			cmd.Content = strings.TrimSpace(load.String())
		}

		commands = append(commands, cmd)
	}
	return commands
}

func parseSections(f *gomacho.File) []Section {
	if len(f.Sections) == 0 {
		return nil
	}

	sections := make([]Section, 0, len(f.Sections))
	for _, section := range f.Sections {
		sections = append(sections, Section{
			Name:   section.Name,
			Filesz: section.Size,
			Memsz:  section.Size,
			Offset: uint64(section.Offset),
			Addr:   section.Addr,
			VMprot: "",
			Flags:  section.Flags.String(),
		})
	}
	return sections
}

func parseCodeSignature(f *gomacho.File) (*CodeSignature, error) {
	raw := f.CodeSignature()
	if raw == nil {
		return nil, nil
	}
	return normalizeCodeSignature(raw), nil
}

func normalizeCodeSignature(raw *gomacho.CodeSignature) *CodeSignature {
	cs := &CodeSignature{
		Signed: len(raw.CodeDirectories) > 0 || len(raw.CMSSignature) > 0,
	}

	if raw.Entitlements != "" {
		var ents map[string]any
		if err := plist.NewDecoder(bytes.NewReader([]byte(raw.Entitlements))).Decode(&ents); err == nil && len(ents) > 0 {
			cs.Entitlements = ents
		}
	}

	if len(raw.Requirements) > 0 {
		cs.Requirements = make([]Requirement, 0, len(raw.Requirements))
		for _, req := range raw.Requirements {
			cs.Requirements = append(cs.Requirements, Requirement{
				Type:   req.Requirements.Type.String(),
				Detail: req.Detail,
			})
		}
	}

	if n := len(raw.CodeDirectories); n > 0 {
		cs.CodeDirectories = make([]CodeDirectory, 0, n)
		bestIdx := bestCodeDirectoryIndex(raw.CodeDirectories)
		for idx, cd := range raw.CodeDirectories {
			entry := CodeDirectory{
				ID:               cd.ID,
				TeamID:           cd.TeamID,
				CDHash:           cd.CDHash,
				Version:          fmt.Sprintf("0x%x", uint32(cd.Header.Version)),
				Flags:            cd.Header.Flags.String(),
				SpecialSlots:     cd.Header.NSpecialSlots,
				CodeSlots:        cd.Header.NCodeSlots,
				HashType:         cd.Header.HashType.String(),
				HashSize:         cd.Header.HashSize,
				Platform:         cd.Header.Platform.String(),
				CodeLimit:        cd.CodeLimit,
				RuntimeVersion:   cd.RuntimeVersion,
				ExecSegmentFlags: cd.Header.ExecSegFlags.String(),
			}
			cs.CodeDirectories = append(cs.CodeDirectories, entry)
			if idx == bestIdx {
				cs.Identifier = entry.ID
				cs.TeamID = entry.TeamID
				cs.CDHash = entry.CDHash
				cs.Adhoc = cd.Header.Flags&cstypes.ADHOC != 0
			}
		}
	}

	if len(raw.CMSSignature) > 0 {
		if p7, err := pkcs7.Parse(raw.CMSSignature); err == nil {
			signer := p7.GetOnlySigner()
			cs.Certificates = make([]Certificate, 0, len(p7.Certificates))
			for i, cert := range p7.Certificates {
				entry := certificateInfo(i, cert, signer)
				cs.Certificates = append(cs.Certificates, entry)
				if entry.IsSigner && cs.Signer == "" {
					cs.Signer = entry.CommonName
					if cs.Signer == "" {
						cs.Signer = entry.Subject
					}
				}
			}
		}
	}

	return cs
}

// bestCodeDirectoryIndex picks the CD with the strongest hash (e.g. Sha256 over Sha1).
func bestCodeDirectoryIndex(cds []cstypes.CodeDirectory) int {
	best := 0
	for i := 1; i < len(cds); i++ {
		if cds[i].Header.HashType > cds[best].Header.HashType {
			best = i
		}
	}
	return best
}

func certificateInfo(index int, cert, signer *x509.Certificate) Certificate {
	entry := Certificate{
		Index:      index,
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		CommonName: cert.Subject.CommonName,
		Serial:     hex.EncodeToString(cert.SerialNumber.Bytes()),
		NotBefore:  cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
	}
	if signer != nil && cert.Equal(signer) {
		entry.IsSigner = true
	}
	return entry
}

func parseSymbols(f *gomacho.File, table *SymbolTable) error {
	// Exports come from the dyld export trie and do not require a Symtab.
	exports, err := f.GetExports()
	if err == nil && len(exports) > 0 {
		table.Exports = make([]Symbol, 0, len(exports))
		for _, export := range exports {
			table.Exports = append(table.Exports, Symbol{
				Name:    export.Name,
				Address: fmt.Sprintf("0x%x", export.Address),
				Type:    export.Type(),
			})
		}
	} else if f.Symtab != nil {
		// Fallback for older/stripped binaries without a usable export trie.
		for _, sym := range f.Symtab.Syms {
			if sym.Type.IsDebugSym() || sym.Type.IsUndefinedSym() || !sym.Type.IsExternalSym() {
				continue
			}
			table.Exports = append(table.Exports, Symbol{
				Name:    sym.Name,
				Address: fmt.Sprintf("0x%x", sym.Value),
				Type:    "external",
			})
		}
	}

	if f.Symtab == nil {
		return nil
	}

	// Imports need Dysymtab; missing it is fine — skip rather than fail parse.
	if importSymbols, impErr := f.ImportedSymbols(); impErr == nil && len(importSymbols) > 0 {
		importLibs := f.ImportedLibraries()
		table.Imports = make(map[string][]string, len(importLibs))
		for _, sym := range importSymbols {
			lib := importLibraryName(sym.Desc.GetLibraryOrdinal(), importLibs)
			table.Imports[lib] = append(table.Imports[lib], sym.Name)
		}
	}

	for _, sym := range f.Symtab.Syms {
		if sym.Type.IsDebugSym() || sym.Type.IsUndefinedSym() || sym.Type.IsExternalSym() {
			continue
		}

		// Skip section symbols (e.g. __text, __data) which are linker artifacts,
		// not actual local functions or variables.
		if sym.Type.IsDefinedInSection() {
			sectIdx := int(sym.Sect) - 1
			if sectIdx >= 0 && sectIdx < len(f.Sections) {
				sect := f.Sections[sectIdx]
				if sym.Name == sect.Name && sym.Value == sect.Addr {
					continue
				}
			}
		}

		table.Locals = append(table.Locals, Symbol{
			Name:    sym.Name,
			Address: fmt.Sprintf("0x%x", sym.Value),
			Type:    sym.GetType(f),
		})
	}

	return nil
}

func importLibraryName(ordinal uint16, importLibs []string) string {
	switch ordinal {
	case types.SELF_LIBRARY_ORDINAL:
		return "self"
	case types.DYNAMIC_LOOKUP_ORDINAL:
		return "dynamic_lookup"
	case types.EXECUTABLE_ORDINAL:
		return "main_executable"
	default:
		if ordinal > 0 && int(ordinal) <= len(importLibs) {
			return importLibs[ordinal-1]
		}
		return "unknown"
	}
}

func parseStrings(f *gomacho.File) Strings {
	cstrs, err := f.GetCStrings()
	if err != nil || cstrs == nil {
		return Strings{}
	}

	total := 0
	for _, strs := range cstrs {
		total += len(strs)
	}

	stringsInfo := Strings{CStrings: make([]string, 0, total)}
	iocs := &ioc.IOCExtractor{}
	for _, strs := range cstrs {
		for str := range strs {
			iocs.Extract(str)
			stringsInfo.CStrings = append(stringsInfo.CStrings, str)
		}
	}
	stringsInfo.IOCs = iocs.Export()
	return stringsInfo
}
