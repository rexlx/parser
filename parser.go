package parser

import (
	"net"
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
		domainMap[strings.ToLower(d)] = struct{}{}
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
			"md5":      regexp.MustCompile(`([a-fA-F\d]{32})`),
			"sha1":     regexp.MustCompile(`([a-fA-F\d]{40})`),
			"sha256":   regexp.MustCompile(`([a-fA-F\d]{64})`),
			"sha512":   regexp.MustCompile(`([a-fA-F\d]{128})`),
			"ipv4":     regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`),
			"ipv6":     regexp.MustCompile(`([a-fA-F\d]{4}(:[a-fA-F\d]{4}){7})`),
			"email":    regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
			"url":      regexp.MustCompile(`((https?|ftp):\/\/[^\s/$.?#].[^\s]*)`),
			"domain":   regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z]{2,3})`),
			"filepath": regexp.MustCompile(`([a-zA-Z0-9.-]+\/[a-zA-Z0-9.-]+)`),
			"filename": regexp.MustCompile(`^[\w\-.]+\.[a-zA-Z]{2,4}$`),
		},
	}
}

func (c *Contextualizer) GetMatches(text string, kind string, regex *regexp.Regexp) []Match {
	matches := regex.FindAllString(text, -1)
	var results []Match

	for _, match := range matches {
		if kind == "url" {
			match = strings.TrimRight(match, "/.,;:")
			match = strings.TrimSuffix(match, "/")
		}

		cleanMatch := strings.ToLower(match)

		switch kind {
		case "filepath":
			if strings.HasPrefix(cleanMatch, "http") ||
				strings.HasPrefix(cleanMatch, "www") ||
				strings.HasPrefix(cleanMatch, "ftp") {
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

		case "domain":
			if c.isDomainIgnored(cleanMatch) {
				continue
			}

			baseDomain, err := extractSecondLevelDomain(cleanMatch)
			// FIX: Removed '&& baseDomain != cleanMatch' to allow base domain to be registered as itself.
			if err == nil && baseDomain != "" {
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
		}
	}
	return results
}

type indexRange struct {
	start int
	end   int
}

func (c *Contextualizer) ExtractAll(text string) map[string][]Match {
	results := make(map[string][]Match)

	var urlRanges []indexRange

	if urlRegex, ok := c.Expressions["url"]; ok {
		indices := urlRegex.FindAllStringIndex(text, -1)
		for _, idx := range indices {
			urlRanges = append(urlRanges, indexRange{idx[0], idx[1]})

			matchVal := text[idx[0]:idx[1]]
			matchVal = strings.TrimRight(matchVal, "/.,;:")
			matchVal = strings.TrimSuffix(matchVal, "/")

			results["url"] = append(results["url"], Match{Value: matchVal, Type: "url"})
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

			if seen[cleanVal] {
				continue
			}

			switch kind {
			case "filepath":
				if strings.HasPrefix(cleanVal, "http") ||
					strings.HasPrefix(cleanVal, "www") ||
					strings.HasPrefix(cleanVal, "ftp") {
					continue
				}

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

			case "ipv4":
				if c.Checks.IgnorePrivateIPs && isPrivateIP(val) {
					continue
				}
			case "email":
				if _, exists := c.Checks.IgnoredEmails[cleanVal]; exists {
					continue
				}
			case "domain":
				if c.isDomainIgnored(cleanVal) {
					continue
				}
			}

			seen[cleanVal] = true
			results[kind] = append(results[kind], Match{Value: val, Type: kind})
		}
	}

	return results
}

func (c *Contextualizer) isDomainIgnored(domain string) bool {
	current := domain
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
	// Check for standard RFC 1918 private ranges
	if ip.IsPrivate() {
		return true
	}

	// FIX: Added checks for loopback and link-local
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}

func extractSecondLevelDomain(domain string) (string, error) {
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", err
	}
	return eTLDPlusOne, nil
}
