package ioc

import (
	"regexp"
	"slices"
	"strings"
)

var (
	ipRegex     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	domainRegex = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	urlRegex    = regexp.MustCompile(`https?://[^\s"'<>]+`)
	emailRegex  = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

	// validTLDs is a whitelist of top-level domains.  It keeps the domain regex
	// from matching strings like "PropertyList-1.0.dtd" whose final label looks
	// like a TLD but is actually a file extension.
	validTLDs = []string{
		"ac", "ad", "ae", "af", "ag", "ai", "al", "ao", "aq", "ar", "as", "at", "au", "aw", "ax", "az",
		"ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bw", "by", "bz",
		"ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cw", "cx", "cy", "cz",
		"de", "dj", "dk", "dm", "do", "dz",
		"ec", "ee", "eg", "er", "es", "et", "eu",
		"fi", "fj", "fk", "fo", "fr",
		"ga", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy",
		"hk", "hm", "hn", "hr", "ht", "hu",
		"id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it",
		"je", "jm", "jo", "jp",
		"ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz",
		"la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly",
		"ma", "mc", "me", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz",
		"na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz",
		"om",
		"pa", "pe", "pf", "pg", "ph", "pk", "pm", "pn", "pr", "ps", "pt", "pw", "py",
		"qa",
		"re", "ro", "ru", "rw",
		"sa", "sb", "sc", "sd", "se", "sg", "si", "sk", "sl", "sm", "sn", "so", "sr", "ss", "su", "sv", "sx", "sy", "sz",
		"tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz",
		"ua", "ug", "uk", "us", "uy", "uz",
		"va", "vc", "ve", "vg", "vi", "vn", "vu",
		"wf", "ws",
		"ye", "yt",
		"za", "zm", "zw",
		"app", "biz", "club", "co", "com", "dev", "info", "me", "name", "net", "online", "org", "site", "top", "xyz",
	}
)

type IOCExtractor struct {
	sets map[string]struct{}
}

func (e *IOCExtractor) Extract(s string) {
	if e.sets == nil {
		e.sets = make(map[string]struct{}, 64)
	}

	// Skip very short or very long strings to reduce noise and cost.
	if len(s) < 5 || len(s) > 512 {
		return
	}

	// Quick pre-filter: must contain a network-related character.
	if !strings.ContainsAny(s, ":.@") && !strings.Contains(s, "://") {
		return
	}

	for _, m := range urlRegex.FindAllString(s, -1) {
		e.sets[m] = struct{}{}
	}
	for _, m := range emailRegex.FindAllString(s, -1) {
		e.sets[m] = struct{}{}
	}
	for _, m := range ipRegex.FindAllString(s, -1) {
		e.sets[m] = struct{}{}
	}
	for _, m := range domainRegex.FindAllString(s, -1) {
		if hasValidTLD(m) {
			e.sets[m] = struct{}{}
		}
	}
}

func (e *IOCExtractor) Export() []string {
	if len(e.sets) > 0 {
		ret := make([]string, 0, len(e.sets))
		for ioc := range e.sets {
			ret = append(ret, ioc)
		}

		return ret
	}

	return nil
}

// hasValidTLD reports whether the last label of s is a known TLD.
func hasValidTLD(s string) bool {
	i := strings.LastIndex(s, ".")
	if i < 0 || i+1 >= len(s) {
		return false
	}
	tld := strings.ToLower(s[i+1:])
	return slices.Contains(validTLDs, tld)
}
