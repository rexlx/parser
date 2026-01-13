package parser

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type Contextualizer struct {
	ID          string
	Expressions map[string]*regexp.Regexp
	Checks      *PrivateChecks
}

type PrivateChecks struct {
	IgnorePrivateIPs bool
	IgnoredDomains   map[string]struct{}
	IgnoredEmails    map[string]struct{}
}

type Match struct {
	Value string
	Type  string
}

func NewContextualizer(ignoreIPs bool, ignoreDomains []string, ignoreEmails []string) *Contextualizer {
	domainMap := make(map[string]struct{}, len(ignoreDomains))
	for _, d := range ignoreDomains {
		domainMap[strings.ToLower(strings.TrimPrefix(d, "."))] = struct{}{}
	}

	emailMap := make(map[string]struct{}, len(ignoreEmails))
	for _, e := range ignoreEmails {
		emailMap[strings.ToLower(e)] = struct{}{}
	}

	return &Contextualizer{
		ID: "contextualizer",
		Checks: &PrivateChecks{
			IgnorePrivateIPs: ignoreIPs,
			IgnoredDomains:   domainMap,
			IgnoredEmails:    emailMap,
		},
		Expressions: map[string]*regexp.Regexp{
			"md5":      regexp.MustCompile(`(?i)\b([a-f\d]{32})\b`),
			"sha1":     regexp.MustCompile(`(?i)\b([a-f\d]{40})\b`),
			"sha256":   regexp.MustCompile(`(?i)\b([a-f\d]{64})\b`),
			"sha512":   regexp.MustCompile(`(?i)\b([a-f\d]{128})\b`),
			"ipv4":     regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`),
			"ipv6":     regexp.MustCompile(`(?i)([a-f\d]{4}(:[a-f\d]{4}){7})`),
			"email":    regexp.MustCompile(`(?i)([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})`),
			"url":      regexp.MustCompile(`(?i)((https?|ftp):\/\/[^\s/$.?#].[^\s]*)`),
			"domain":   regexp.MustCompile(`(?i)([a-z0-9.-]+\.[a-z]{2,24})\b`),
			"filepath": regexp.MustCompile(`([a-zA-Z0-9.-]+\/[a-zA-Z0-9.-]+)`),
			"filename": regexp.MustCompile(`^[\w\-.]+\.[a-zA-Z]{2,4}$`),
		},
	}
}

func (c *Contextualizer) GetMatches(text string, kind string, regex *regexp.Regexp) []Match {
	matches := regex.FindAllString(text, -1)
	var results []Match
	seen := make(map[string]bool)

	for _, match := range matches {
		if kind == "url" {
			match = strings.TrimRight(match, "/.,;:")
			match = strings.TrimSuffix(match, "/")
		}

		cleanMatch := strings.ToLower(match)
		if seen[cleanMatch] {
			continue
		}

		switch kind {
		case "url":
			if u, err := url.Parse(cleanMatch); err == nil {
				if c.isDomainIgnored(u.Hostname()) {
					continue
				}
			}
		case "filepath":
			if strings.HasPrefix(cleanMatch, "http") || strings.HasPrefix(cleanMatch, "www") || strings.HasPrefix(cleanMatch, "ftp") {
				continue
			}
		case "ipv4":
			if c.Checks.IgnorePrivateIPs && isPrivateIP(match) {
				continue
			}
		case "email":
			if _, exists := c.Checks.IgnoredEmails[cleanMatch]; exists {
				continue
			}
			parts := strings.Split(cleanMatch, "@")
			if len(parts) == 2 && c.isDomainIgnored(parts[1]) {
				continue
			}
		case "domain":
			if c.isDomainIgnored(cleanMatch) {
				continue
			}
			baseDomain, err := extractSecondLevelDomain(cleanMatch)
			if err == nil && baseDomain != "" && baseDomain != cleanMatch {
				if !c.isDomainIgnored(baseDomain) {
					results = append(results, Match{Value: baseDomain, Type: "base_domain"})
				}
			}
		}

		finalValue := match
		if kind == "domain" || kind == "email" {
			finalValue = cleanMatch
		}

		if finalValue != "" {
			results = append(results, Match{Value: finalValue, Type: kind})
			seen[cleanMatch] = true
		}
	}
	return results
}

func (c *Contextualizer) ExtractAll(text string) map[string][]Match {
	results := make(map[string][]Match)
	urlRanges := []struct{ start, end int }{}

	// Handle URLs first to avoid partial matches in other types
	if urlRegex, ok := c.Expressions["url"]; ok {
		indices := urlRegex.FindAllStringIndex(text, -1)
		seen := make(map[string]bool)
		for _, idx := range indices {
			val := strings.TrimSuffix(strings.TrimRight(text[idx[0]:idx[1]], "/.,;:"), "/")
			cleanVal := strings.ToLower(val)

			if u, err := url.Parse(cleanVal); err == nil && c.isDomainIgnored(u.Hostname()) {
				continue
			}

			if !seen[cleanVal] {
				urlRanges = append(urlRanges, struct{ start, end int }{idx[0], idx[1]})
				results["url"] = append(results["url"], Match{Value: val, Type: "url"})
				seen[cleanVal] = true
			}
		}
	}

	for kind, regex := range c.Expressions {
		if kind == "url" {
			continue
		}

		rawMatches := regex.FindAllStringIndex(text, -1)
		seen := make(map[string]bool)

		for _, idx := range rawMatches {
			val := text[idx[0]:idx[1]]
			cleanVal := strings.ToLower(val)

			// Basic overlap prevention
			isInsideUrl := false
			for _, r := range urlRanges {
				if idx[0] >= r.start && idx[1] <= r.end {
					isInsideUrl = true
					break
				}
			}
			if isInsideUrl {
				continue
			}

			if seen[cleanVal] {
				continue
			}

			switch kind {
			case "filepath":
				if strings.HasPrefix(cleanVal, "http") || strings.HasPrefix(cleanVal, "www") {
					continue
				}
			case "ipv4":
				if c.Checks.IgnorePrivateIPs && isPrivateIP(val) {
					continue
				}
			case "email":
				if _, exists := c.Checks.IgnoredEmails[cleanVal]; exists {
					continue
				}
				parts := strings.Split(cleanVal, "@")
				if len(parts) == 2 && c.isDomainIgnored(parts[1]) {
					continue
				}
			case "domain":
				if c.isDomainIgnored(cleanVal) {
					continue
				}
				// Add base domain for consistency with GetMatches
				base, err := extractSecondLevelDomain(cleanVal)
				if err == nil && base != "" && base != cleanVal {
					if !c.isDomainIgnored(base) {
						results["base_domain"] = append(results["base_domain"], Match{Value: base, Type: "base_domain"})
					}
				}
			}

			seen[cleanVal] = true
			results[kind] = append(results[kind], Match{Value: val, Type: kind})
		}
	}
	return results
}

func (c *Contextualizer) isDomainIgnored(domain string) bool {
	current := strings.TrimSuffix(strings.ToLower(domain), ".")
	for {
		if _, exists := c.Checks.IgnoredDomains[current]; exists {
			return true
		}
		idx := strings.Index(current, ".")
		if idx == -1 {
			break
		}
		current = current[idx+1:]
	}
	return false
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func extractSecondLevelDomain(domain string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(domain)
}
