package oauth

import (
	"fmt"
	"regexp"
)

// GroupMappingRule maps an upstream provider group name to a local group name.
type GroupMappingRule struct {
	Pattern     string `mapstructure:"pattern" json:"pattern" yaml:"pattern"`
	Replacement string `mapstructure:"replacement" json:"replacement" yaml:"replacement"`
}

type compiledRule struct {
	pattern     *regexp.Regexp
	replacement string
}

// GroupMapper maps upstream provider group names to local group names using an
// ordered list of regex rules. First-match-wins per group; a group matching no
// rule is dropped. Go regexp is RE2, so matching is linear-time (ReDoS-safe).
type GroupMapper struct {
	rules []compiledRule
}

// NewGroupMapper compiles the configured rules. A nil or empty list yields the
// identity mapper.
func NewGroupMapper(rules []GroupMappingRule) (*GroupMapper, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for i, rule := range rules {
		if rule.Pattern == "" {
			return nil, fmt.Errorf("group_mappings[%d] pattern must not be empty", i)
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("group_mappings[%d] pattern %q: %w", i, rule.Pattern, err)
		}
		compiled = append(compiled, compiledRule{pattern: re, replacement: rule.Replacement})
	}
	return &GroupMapper{rules: compiled}, nil
}

// Active reports whether any mapping rules are configured.
func (m *GroupMapper) Active() bool {
	return m != nil && len(m.rules) > 0
}

// MapIfActive applies Map when rules are configured and returns nil otherwise.
func (m *GroupMapper) MapIfActive(providerGroups []string) []string {
	if m.Active() {
		return m.Map(providerGroups)
	}
	return nil
}

// Map applies the ordered rules to each provider group. First-match-wins per
// group; a group matching no rule is dropped. Output order is deterministic and
// duplicates are removed preserving first occurrence. With no rules it returns
// the input unchanged (identity).
func (m *GroupMapper) Map(providerGroups []string) []string {
	out := make([]string, 0, len(providerGroups))
	seen := make(map[string]struct{}, len(providerGroups))
	for _, group := range providerGroups {
		mapped, ok := m.mapGroup(group)
		if !ok || mapped == "" {
			continue
		}
		if _, dup := seen[mapped]; dup {
			continue
		}
		seen[mapped] = struct{}{}
		out = append(out, mapped)
	}
	return out
}

func (m *GroupMapper) mapGroup(group string) (string, bool) {
	if m == nil || len(m.rules) == 0 {
		return group, true
	}
	for _, rule := range m.rules {
		if idx := rule.pattern.FindStringSubmatchIndex(group); idx != nil {
			return string(rule.pattern.ExpandString(nil, rule.replacement, group, idx)), true
		}
	}
	return "", false
}
