package macho

import (
	"bytes"
	"fmt"
	"strings"

	gomacho "github.com/blacktop/go-macho"
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
	Certificates    []Certificate   `json:"certificates"`
	Identifier      string          `json:"identifier"`
	TeamID          string          `json:"team_id"`
	CDHash          string          `json:"cdhash"`
	Entitlements    map[string]any  `json:"entitlements"`
	Requirements    []Requirement   `json:"requirements"`
	CodeDirectories []CodeDirectory `json:"code_directories"`
}

type Requirement struct {
	Type   string `json:"type,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type Certificate struct {
	Index   int    `json:"index"`
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

type CodeDirectory struct {
	ID               string `json:"id,omitempty"`
	TeamID           string `json:"team_id,omitempty"`
	CDHash           string `json:"cdhash,omitempty"`
	Version          uint32 `json:"version,omitempty"`
	Flags            uint32 `json:"flags,omitempty"`
	FlagsStr         string `json:"flags_str,omitempty"`
	HashOffset       uint32 `json:"hash_offset,omitempty"`
	IdentifierOffset uint32 `json:"identifier_offset,omitempty"`
	SpecialSlots     uint32 `json:"special_slots,omitempty"`
	CodeSlots        uint32 `json:"code_slots,omitempty"`
	HashSize         uint8  `json:"hash_size,omitempty"`
	HashType         uint8  `json:"hash_type,omitempty"`
	HashTypeStr      string `json:"hash_type_str,omitempty"`
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
	for _, load := range f.Loads {
		if load.Command() != types.LC_CODE_SIGNATURE {
			continue
		}

		raw, ok := load.(*gomacho.CodeSignature)
		if !ok || raw == nil {
			continue
		}
		return normalizeCodeSignature(raw)
	}

	return nil, nil
}

func normalizeCodeSignature(raw *gomacho.CodeSignature) (*CodeSignature, error) {
	cs := &CodeSignature{}
	cs.Signed = len(raw.CodeDirectories) > 0

	if raw.Entitlements != "" {
		_ = plist.NewDecoder(bytes.NewReader([]byte(raw.Entitlements))).Decode(&cs.Entitlements)
		// Entitlements plist may be malformed; ignore the error and leave the map empty.
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

	if len(raw.CodeDirectories) > 0 {
		cs.CodeDirectories = make([]CodeDirectory, 0, len(raw.CodeDirectories))
		for idx, cd := range raw.CodeDirectories {
			entry := CodeDirectory{
				ID:      cd.ID,
				TeamID:  cd.TeamID,
				CDHash:  cd.CDHash,
				Version: uint32(cd.Header.Version),

				Flags:    uint32(cd.Header.Flags),
				FlagsStr: cd.Header.Flags.String(),

				HashOffset:       cd.Header.HashOffset,
				IdentifierOffset: cd.Header.IdentOffset,
				SpecialSlots:     cd.Header.NSpecialSlots,
				CodeSlots:        cd.Header.NCodeSlots,
				HashType:         uint8(cd.Header.HashType),
				HashTypeStr:      cd.Header.HashType.String(),
				HashSize:         cd.Header.HashSize,
				Platform:         cd.Header.Platform.String(),
				CodeLimit:        cd.CodeLimit,
				RuntimeVersion:   cd.RuntimeVersion,
				ExecSegmentFlags: cd.Header.ExecSegFlags.String(),
			}
			cs.CodeDirectories = append(cs.CodeDirectories, entry)
			if idx == 0 {
				cs.Identifier = entry.ID
				cs.TeamID = entry.TeamID
				cs.CDHash = entry.CDHash
			}
		}
	}

	// parse CMSSignature (best-effort)
	if p7, err := pkcs7.Parse(raw.CMSSignature); err == nil {
		cs.Certificates = make([]Certificate, 0, len(p7.Certificates))
		for i, cert := range p7.Certificates {
			cs.Certificates = append(cs.Certificates, Certificate{
				Index:   i,
				Subject: cert.Subject.String(),
				Issuer:  cert.Issuer.String(),
			})
		}
	}

	return cs, nil
}

func parseSymbols(f *gomacho.File, table *SymbolTable) error {
	if f.Symtab == nil {
		return nil
	}

	importSymbols, err := f.ImportedSymbols()
	if err != nil {
		return err
	}
	importLibs := f.ImportedLibraries()
	if len(importSymbols) > 0 {
		table.Imports = make(map[string][]string)
	}

	for _, sym := range importSymbols {
		lib := "unknown"
		libord := int(sym.Desc.GetLibraryOrdinal())
		switch libord {
		case 0:
			lib = "self"
		case 0xfe:
			lib = "dynamic_lookup"
		case 0xff:
			lib = "main_executable"
		default:
			if libord > 0 && libord <= len(importLibs) {
				lib = importLibs[libord-1]
			}
		}

		table.Imports[lib] = append(table.Imports[lib], sym.Name)
	}

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
	} else {
		// Fallback: extract exports from symtab external symbols
		// (for older or stripped binaries without dyld export trie).
		for _, sym := range f.Symtab.Syms {
			if sym.Type.IsUndefinedSym() {
				continue
			}
			if !sym.Type.IsExternalSym() {
				continue
			}
			table.Exports = append(table.Exports, Symbol{
				Name:    sym.Name,
				Address: fmt.Sprintf("0x%x", sym.Value),
				Type:    sym.GetType(f),
			})
		}
	}

	for _, sym := range f.Symtab.Syms {
		if sym.Type.IsUndefinedSym() {
			continue
		}

		if sym.Type.IsExternalSym() {
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
