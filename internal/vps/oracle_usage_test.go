package vps

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOracleDailyUsageIncludesCurrentUTCDay(t *testing.T) {
	for _, when := range []string{"2026-09-21T19:29:57Z", "2026-10-01T00:00:00Z", "2026-12-31T23:59:59Z", "2026-10-01T02:00:00+08:00"} {
		t.Run(when, func(t *testing.T) {
			s, fake, req := testService(t, "oracle")
			now, err := time.Parse(time.RFC3339, when)
			if err != nil {
				t.Fatal(err)
			}
			s.options.Now = func() time.Time { return now }
			queried := false
			s.options.Run = func(ctx context.Context, executable string, args []string) ([]byte, error) {
				if strings.Contains(strings.Join(args, " "), "usage-api usage-summary") {
					queried = true
					get := func(flag string) time.Time {
						for i := range args {
							if args[i] == flag && i+1 < len(args) {
								parsed, e := time.Parse(time.RFC3339, args[i+1])
								if e != nil {
									t.Fatal(e)
								}
								return parsed
							}
						}
						t.Fatalf("missing %s", flag)
						return time.Time{}
					}
					start, end := get("--time-usage-started"), get("--time-usage-ended")
					if start != start.Truncate(24*time.Hour) || end != end.Truncate(24*time.Hour) {
						return nil, fmt.Errorf("OCI DAILY precision requires UTC midnight")
					}
					u := now.UTC()
					wantStart := time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
					wantEnd := time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
					if !start.Equal(wantStart) || !end.Equal(wantEnd) {
						t.Fatalf("usage interval omits current UTC day or crosses month incorrectly: %s to %s", start, end)
					}
				}
				return fake.run(ctx, executable, args)
			}
			if _, err = s.PlanCreate(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			if !queried || len(fake.mutations) != 0 {
				t.Fatal("preview must query usage without mutating cloud resources")
			}
		})
	}
}

func TestOracleDailyUsageRetainsReportingLagBudget(t *testing.T) {
	s, fake, req := testService(t, "oracle")
	s.options.Run = func(ctx context.Context, executable string, args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "usage-api usage-summary") {
			return []byte(`{"data":{"items":[{"sku-part-number":"B93297","computed-quantity":1300},{"sku-part-number":"B93298","computed-quantity":7800}]}}`), nil
		}
		return fake.run(ctx, executable, args)
	}
	if _, err := s.PlanCreate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "free allowance is insufficient") {
		t.Fatalf("near-exhausted free allowance was not refused: %v", err)
	}
}
