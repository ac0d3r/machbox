package filebase

import (
	"bytes"
	"encoding/binary"
)

const (
	mhMagic    = 0xFEEDFACE
	mhCigam    = 0xCEFAEDFE
	mhMagic64  = 0xFEEDFACF
	mhCigam64  = 0xCFFAEDFE
	fatMagic   = 0xCAFEBABE
	fatCigam   = 0xBEBAFECA
	fatMagic64 = 0xCAFEBABF
	fatCigam64 = 0xBFBAFECA

	mhExecute = 0x2
	mhDylib   = 0x6
)

type kind uint8

const (
	kindUnknown kind = iota
	kindMachO
	kindDylib
	kindZIP
	kindXAR
	kindDMG
)

type sniffResult struct {
	Kind kind
	MIME string
}

func sniffHeader(header []byte) sniffResult {
	var sn sniffResult
	if len(header) < 4 {
		return sn
	}

	switch {
	case bytes.HasPrefix(header, []byte{'P', 'K', 0x03, 0x04}),
		bytes.HasPrefix(header, []byte{'P', 'K', 0x05, 0x06}),
		bytes.HasPrefix(header, []byte{'P', 'K', 0x07, 0x08}):
		sn.Kind = kindZIP
		return sn

	case bytes.HasPrefix(header, []byte("xar!")):
		sn.Kind = kindXAR
		return sn
	}

	magic := binary.LittleEndian.Uint32(header[:4])
	switch magic {
	case mhMagic, mhCigam, mhMagic64, mhCigam64:
		if machOFileType(header, magic) == mhDylib {
			sn.Kind = kindDylib
		} else {
			sn.Kind = kindMachO
		}
		return sn

	case fatMagic, fatCigam, fatMagic64, fatCigam64:
		sn.Kind = kindMachO
		// Fat headers are big-endian; try to classify the first slice when present.
		if ft, ok := fatFirstFileType(header); ok && ft == mhDylib {
			sn.Kind = kindDylib
		}
		return sn
	}

	return sn
}

func sniffDMGTrailer(trailer []byte) bool {
	// UDIF footer ("koly" block) occupies the last 512 bytes.
	return len(trailer) >= 4 && string(trailer[:4]) == "koly"
}

func machOFileType(header []byte, magic uint32) uint32 {
	if len(header) < 16 {
		return 0
	}
	// magic was read as little-endian from the first 4 bytes:
	// MH_MAGIC/_64 => little-endian Mach-O; MH_CIGAM/_64 => big-endian.
	var bo binary.ByteOrder = binary.LittleEndian
	switch magic {
	case mhCigam, mhCigam64:
		bo = binary.BigEndian
	}
	return bo.Uint32(header[12:16])
}

func fatFirstFileType(header []byte) (uint32, bool) {
	// fat_header: magic(4) + nfat_arch(4); fat_arch: cputype, cpusubtype, offset, size, align.
	if len(header) < 28 {
		return 0, false
	}
	nfat := binary.BigEndian.Uint32(header[4:8])
	if nfat == 0 {
		return 0, false
	}
	offset := binary.BigEndian.Uint32(header[16:20])
	if offset+16 > uint32(len(header)) {
		return 0, false
	}
	slice := header[offset:]
	magic := binary.LittleEndian.Uint32(slice[:4])
	switch magic {
	case mhMagic, mhCigam, mhMagic64, mhCigam64:
		return machOFileType(slice, magic), true
	default:
		return 0, false
	}
}
