package rulework

import (
	"context"
	"errors"
	"fmt"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
)

// MaxRuleBatchSize bounds focused analysis and the durable receipt size.
const MaxRuleBatchSize = 256

func parseQuickBatch(raw []string) ([]rulecheck.Rule, error) {
	if len(raw) == 0 || len(raw) > MaxRuleBatchSize {
		return nil, fmt.Errorf("supply between 1 and %d rules", MaxRuleBatchSize)
	}
	rules := make([]rulecheck.Rule, 0, len(raw))
	seen, policies := map[string]bool{}, map[string]string{}
	size := 0
	for i, expression := range raw {
		rule, err := rulecheck.Parse(expression)
		if err != nil {
			if len(raw) == 1 {
				return nil, err
			}
			return nil, fmt.Errorf("rule #%d: %w", i+1, err)
		}
		canonical := rule.String()
		if seen[canonical] {
			continue
		}
		if policy, ok := policies[rule.SelectorKey()]; ok && policy != rule.Policy {
			return nil, fmt.Errorf("selector_conflict: batch rule #%d uses policy %q but the same selector already requests %q", i+1, rule.Policy, policy)
		}
		size += len(canonical)
		if size > 128<<10 {
			return nil, errors.New("rule batch exceeds 128 KiB")
		}
		policies[rule.SelectorKey()], seen[canonical] = rule.Policy, true
		rules = append(rules, rule)
	}
	return rules, nil
}

func quickExpressions(rules []rulecheck.Rule) []string {
	result := make([]string, 0, len(rules))
	for _, rule := range rules {
		result = append(result, rule.String())
	}
	return result
}

// Verify the complete newly prepended block in order, then every requested
// rule, including retained declarations. Runtime cannot expose no-resolve.
func runtimeBatchExpressions(ctx context.Context, target config.Target, requested, added []string, opts Options) (bool, error) {
	wanted, err := parseQuickBatch(requested)
	if err != nil {
		return false, err
	}
	prepended, err := parseQuickBatch(added)
	if err != nil {
		return false, err
	}
	known := map[string]bool{}
	for _, rule := range wanted {
		known[rule.String()] = true
	}
	for _, rule := range prepended {
		if !known[rule.String()] {
			return false, errors.New("batch receipt contains an unrequested added rule")
		}
	}
	client, cleanup, err := openCore(ctx, target, true, opts)
	if err != nil {
		return false, err
	}
	defer cleanup()
	object, err := client.Rules(ctx)
	if err != nil {
		return false, err
	}
	list, err := runtimeRuleList(object)
	if err != nil || len(list) < len(prepended) {
		return false, err
	}
	for i, rule := range prepended {
		if !runtimeHasRule(list[i:i+1], rule) {
			return false, nil
		}
	}
	for _, rule := range wanted {
		if !runtimeHasRule(list, rule) {
			return false, nil
		}
	}
	return true, nil
}
