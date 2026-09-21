package vps

import (
	"context"
	"errors"
	"testing"
)

func TestOracleCLIEmptySuccessfulFullList(t *testing.T) {
	s, _, req := testService(t, "oracle")
	s.options.Run = func(context.Context, string, []string) ([]byte, error) { return nil, nil }
	args := []string{"compute", "instance", "list", "--compartment-id", req.CompartmentID, "--all"}
	got, err := s.call(context.Background(), req, args...)
	rows, parseErr := strictItems(got, "data")
	if err != nil || parseErr != nil || len(rows) != 0 {
		t.Fatalf("OCI empty-list rendering not handled: %v %v %v", got, err, parseErr)
	}
	for _, partial := range [][]string{{"compute", "instance", "list"}, {"compute", "instance", "get"}, append(append([]string{}, args...), "--query", "data"), append(append([]string{}, args...), "--page", "next")} {
		got, _ = s.call(context.Background(), req, partial...)
		if _, err = strictItems(got, "data"); err == nil {
			t.Fatalf("blank partial/non-list response treated as confirmed absence: %v", partial)
		}
	}
	s.options.Run = func(context.Context, string, []string) ([]byte, error) {
		return nil, errors.New("authentication failed")
	}
	if _, err = s.call(context.Background(), req, args...); err == nil {
		t.Fatal("failed OCI request treated as empty inventory")
	}
	s.options.Run = func(context.Context, string, []string) ([]byte, error) { return []byte(`{}`), nil }
	if _, err = s.call(context.Background(), req, args...); err == nil {
		t.Fatal("malformed nonempty list treated as empty inventory")
	}
}
