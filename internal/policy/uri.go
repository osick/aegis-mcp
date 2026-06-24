package policy

import (
	"net/url"
	"path"
	"strings"
)

// IsResourceAllowed canonicalizes the URI (decode, normalize, reject traversal)
// before matching against the profile's resource patterns.
func (p *Policy) IsResourceAllowed(profile, rawURI string) bool {
	cp, ok := p.profiles[profile]
	if !ok {
		return false
	}
	canon, ok := canonicalizeURI(rawURI)
	if !ok {
		return false
	}
	for _, pat := range cp.resources {
		canonPat, ok := canonicalizeURI(stripGlob(pat))
		if !ok {
			continue
		}
		if matchURIGlob(pat, canon, canonPat) {
			return true
		}
	}
	return false
}

// canonicalizeURI returns scheme + host + cleaned, decoded path, or ok=false if the
// path escapes its root after normalization (path traversal).
//
// The host/authority MUST be retained: resource templates scope by authority
// (e.g. github://repo/pulls/{id}, file://host/path), so dropping it would let
// github://attacker-repo/... match a pattern written for github://my-repo/...
func canonicalizeURI(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	cleaned := u.Path
	if cleaned != "" {
		cleaned = path.Clean(cleaned)
	}
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", false
	}
	return u.Scheme + "://" + u.Host + cleaned, true
}

func stripGlob(pat string) string {
	pat = strings.TrimSuffix(pat, "/**")
	pat = strings.TrimSuffix(pat, "/*")
	return pat
}

func matchURIGlob(pattern, canonURI, canonPrefix string) bool {
	switch {
	case strings.HasSuffix(pattern, "/**"):
		return canonURI == canonPrefix || strings.HasPrefix(canonURI, canonPrefix+"/")
	case strings.HasSuffix(pattern, "/*"):
		if !strings.HasPrefix(canonURI, canonPrefix+"/") {
			return false
		}
		rest := strings.TrimPrefix(canonURI, canonPrefix+"/")
		return rest != "" && !strings.Contains(rest, "/")
	default:
		return canonURI == canonPrefix
	}
}
