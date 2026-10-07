package ioc

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	ipv4Regex   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	domainRegex = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b`)
	urlRegex    = regexp.MustCompile(`https?://[^\s"'<>]+`)
	emailRegex  = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}`)

	// urlTrailCutset strips punctuation commonly left attached to URLs in prose.
	urlTrailCutset = ".,;:!?)]}'\"\\"

	// validTLDs is a whitelist of top-level domains. It keeps the domain regex
	// from matching strings like "PropertyList-1.0.dtd" whose final label looks
	// like a TLD but is actually a file extension.
	//
	// Deliberately omitted (common file extensions / binary noise):
	// rs, pl, md, sh, am, fm, st, so, ls, js, ts, go, py, c, h, o, a, ...
	validTLDs = map[string]struct{}{
		// ccTLDs
		"ac": {}, "ad": {}, "ae": {}, "af": {}, "ag": {}, "ai": {}, "al": {}, "ao": {}, "aq": {}, "ar": {},
		"as": {}, "at": {}, "au": {}, "aw": {}, "ax": {}, "az": {},
		"ba": {}, "bb": {}, "bd": {}, "be": {}, "bf": {}, "bg": {}, "bh": {}, "bi": {}, "bj": {}, "bm": {},
		"bn": {}, "bo": {}, "br": {}, "bs": {}, "bt": {}, "bw": {}, "by": {}, "bz": {},
		"ca": {}, "cc": {}, "cd": {}, "cf": {}, "cg": {}, "ch": {}, "ci": {}, "ck": {}, "cl": {}, "cm": {},
		"cn": {}, "co": {}, "cr": {}, "cu": {}, "cv": {}, "cw": {}, "cx": {}, "cy": {}, "cz": {},
		"de": {}, "dj": {}, "dk": {}, "dm": {}, "do": {}, "dz": {},
		"ec": {}, "ee": {}, "eg": {}, "er": {}, "es": {}, "et": {}, "eu": {},
		"fi": {}, "fj": {}, "fk": {}, "fo": {}, "fr": {},
		"ga": {}, "gd": {}, "ge": {}, "gf": {}, "gg": {}, "gh": {}, "gi": {}, "gl": {}, "gm": {}, "gn": {},
		"gp": {}, "gq": {}, "gr": {}, "gs": {}, "gt": {}, "gu": {}, "gw": {}, "gy": {},
		"hk": {}, "hm": {}, "hn": {}, "hr": {}, "ht": {}, "hu": {},
		"id": {}, "ie": {}, "il": {}, "im": {}, "in": {}, "io": {}, "iq": {}, "ir": {}, "is": {}, "it": {},
		"je": {}, "jm": {}, "jo": {}, "jp": {},
		"ke": {}, "kg": {}, "kh": {}, "ki": {}, "km": {}, "kn": {}, "kp": {}, "kr": {}, "kw": {}, "ky": {},
		"kz": {},
		"la": {}, "lb": {}, "lc": {}, "li": {}, "lk": {}, "lr": {}, "lt": {}, "lu": {}, "lv": {}, "ly": {},
		"ma": {}, "mc": {}, "me": {}, "mg": {}, "mh": {}, "mk": {}, "ml": {}, "mm": {}, "mn": {}, "mo": {},
		"mp": {}, "mq": {}, "mr": {}, "ms": {}, "mt": {}, "mu": {}, "mv": {}, "mw": {}, "mx": {}, "my": {},
		"mz": {},
		"na": {}, "nc": {}, "ne": {}, "nf": {}, "ng": {}, "ni": {}, "nl": {}, "no": {}, "np": {}, "nr": {},
		"nu": {}, "nz": {},
		"om": {},
		"pa": {}, "pe": {}, "pf": {}, "pg": {}, "ph": {}, "pk": {}, "pm": {}, "pn": {}, "pr": {}, "ps": {},
		"pt": {}, "pw": {}, "py": {},
		"qa": {},
		"re": {}, "ro": {}, "ru": {}, "rw": {},
		"sa": {}, "sb": {}, "sc": {}, "sd": {}, "se": {}, "sg": {}, "si": {}, "sk": {}, "sl": {}, "sm": {},
		"sn": {}, "sr": {}, "ss": {}, "su": {}, "sv": {}, "sx": {}, "sy": {}, "sz": {},
		"tc": {}, "td": {}, "tf": {}, "tg": {}, "th": {}, "tj": {}, "tk": {}, "tl": {}, "tm": {}, "tn": {},
		"to": {}, "tr": {}, "tt": {}, "tv": {}, "tw": {}, "tz": {},
		"ua": {}, "ug": {}, "uk": {}, "us": {}, "uy": {}, "uz": {},
		"va": {}, "vc": {}, "ve": {}, "vg": {}, "vi": {}, "vn": {}, "vu": {},
		"wf": {}, "ws": {},
		"ye": {}, "yt": {},
		"za": {}, "zm": {}, "zw": {},

		// sponsored / legacy gTLDs
		"edu": {}, "gov": {}, "mil": {}, "int": {},
		"arpa": {}, "aero": {}, "asia": {}, "cat": {}, "coop": {}, "jobs": {}, "mobi": {}, "museum": {},
		"post": {}, "pro": {}, "tel": {}, "xxx": {},

		// common gTLDs seen in malware / modern infra
		"app": {}, "biz": {}, "blog": {}, "cloud": {}, "club": {}, "com": {}, "dev": {}, "fun": {},
		"info": {}, "link": {}, "live": {}, "name": {}, "net": {}, "online": {}, "org": {}, "shop": {},
		"site": {}, "store": {}, "tech": {}, "top": {}, "vip": {}, "xyz": {},
	}

	// safeTwoLetterTLDs may appear in bare two-label domains (example.io).
	// Other two-letter TLDs require 3+ labels (e.g. example.co.uk) to limit
	// filename / short-token false positives.
	safeTwoLetterTLDs = map[string]struct{}{
		"ai": {}, "au": {}, "be": {}, "br": {}, "ca": {}, "cc": {}, "ch": {}, "cn": {}, "co": {},
		"de": {}, "dk": {}, "es": {}, "eu": {}, "fi": {}, "fr": {}, "ie": {}, "il": {}, "in": {},
		"io": {}, "it": {}, "jp": {}, "kr": {}, "me": {}, "nl": {}, "no": {}, "nz": {},
		"pt": {}, "ru": {}, "se": {}, "sg": {}, "tv": {}, "tw": {}, "ua": {}, "uk": {}, "us": {},
		"za": {},
	}

	// fileLikeTLDs are gTLDs that collide with common file extensions. Allow
	// them only in 3+ label domains (a.b.app), never as name.zip.
	fileLikeTLDs = map[string]struct{}{
		"app": {}, "dev": {}, "zip": {}, "mov": {}, "apk": {}, "dmg": {}, "pkg": {}, "exe": {},
		"dll": {}, "jar": {}, "war": {}, "gz": {}, "xz": {}, "bz2": {},
	}

	reverseDNSHeads = map[string]struct{}{
		"com": {}, "org": {}, "net": {}, "edu": {}, "gov": {}, "mil": {}, "io": {}, "co": {},
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
	if !strings.ContainsAny(s, ":.@") {
		return
	}

	// Work on a copy where URLs/emails are blanked so their local-parts and
	// path noise are not re-matched as bare domains.
	work := []byte(s)

	for _, m := range urlRegex.FindAllStringIndex(s, -1) {
		raw := s[m[0]:m[1]]
		cleaned := trimURL(raw)
		if cleaned == "" {
			continue
		}
		e.add(cleaned)
		if host := urlHost(cleaned); host != "" {
			if ip := net.ParseIP(host); ip != nil {
				if ip.To4() != nil {
					e.add(ip.String())
				}
			} else if isValidDomain(host) {
				e.add(host)
			}
		}
		blankRange(work, m[0], m[1])
	}

	for _, m := range emailRegex.FindAllStringIndex(s, -1) {
		raw := s[m[0]:m[1]]
		if isValidEmail(raw) {
			e.add(raw)
			if at := strings.LastIndex(raw, "@"); at > 0 {
				e.add(raw[at+1:])
			}
		}
		blankRange(work, m[0], m[1])
	}

	workStr := string(work)
	for _, m := range ipv4Regex.FindAllString(workStr, -1) {
		e.add(m)
	}
	for _, m := range domainRegex.FindAllString(workStr, -1) {
		if isValidDomain(m) {
			e.add(m)
		}
	}
}

func (e *IOCExtractor) add(v string) {
	if v == "" {
		return
	}
	e.sets[v] = struct{}{}
}

func (e *IOCExtractor) Export() []string {
	if len(e.sets) == 0 {
		return nil
	}
	ret := make([]string, 0, len(e.sets))
	for ioc := range e.sets {
		ret = append(ret, ioc)
	}
	sort.Strings(ret)
	return ret
}

func blankRange(b []byte, start, end int) {
	for i := start; i < end; i++ {
		b[i] = ' '
	}
}

func trimURL(u string) string {
	return strings.TrimRight(u, urlTrailCutset)
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	return strings.TrimPrefix(host, "www.")
}

func isValidEmail(addr string) bool {
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at+1 >= len(addr) {
		return false
	}
	return isValidDomain(addr[at+1:])
}

func isValidDomain(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if len(domain) < 4 || len(domain) > 253 {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}

	tld := labels[len(labels)-1]
	if _, ok := validTLDs[tld]; !ok {
		return false
	}

	if len(labels) == 2 {
		// name.zip / Foo.app — extension collision.
		if _, ok := fileLikeTLDs[tld]; ok {
			return false
		}
		// Two-label domains with risky two-letter TLDs are usually filenames
		// (e.g. libfoo.so) rather than real hosts.
		if len(tld) == 2 {
			if _, ok := safeTwoLetterTLDs[tld]; !ok {
				return false
			}
		}
	}

	// Reverse-DNS / bundle identifiers common in Mach-O strings
	// (com.apple.*, CFBundle.com.apple.ls, ...).
	if isBundleLike(labels) {
		return false
	}

	return true
}

func isBundleLike(labels []string) bool {
	if len(labels) < 3 {
		return false
	}
	head := labels[0]
	if _, ok := reverseDNSHeads[head]; ok {
		return true
	}
	if strings.HasPrefix(head, "cfbundle") || strings.HasPrefix(head, "ns") {
		return true
	}
	return false
}
