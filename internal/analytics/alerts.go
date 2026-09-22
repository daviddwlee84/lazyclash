package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

func (s *Store) EvaluateAlerts(ctx context.Context, c AlertConfig, now time.Time) ([]Alert, error) {
	result := []Alert{}
	if !c.Enabled {
		return result, nil
	}
	if s.readOnly {
		return result, ErrReadOnly
	}
	if err := validateAlerts(c); err != nil {
		return result, err
	}
	zone := s.timezone(ctx)
	if c.Timezone != "" && c.Timezone != zone {
		return result, errors.New("alert timezone must match recorded daily buckets")
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return result, err
	}
	start := dayStart(now, loc)
	day := start.Format("2006-01-02")
	thresholds := append([]int64(nil), c.ThresholdGiB...)
	if len(thresholds) == 0 {
		thresholds = []int64{20, 50, 100}
	}
	sort.Slice(thresholds, func(i, j int) bool { return thresholds[i] < thresholds[j] })
	status, err := s.Status(ctx)
	if err != nil {
		return result, err
	}
	wanted := map[string]bool{}
	for _, id := range c.SourceIDs {
		wanted[id] = true
	}
	valid := map[string]bool{}
	for _, src := range status.Sources {
		if src.Scope == "host" && (src.Kind == "interface" || src.Kind == "host-interface" || src.Kind == "vnstat") {
			valid[src.SourceID] = true
		}
	}
	for id := range wanted {
		if !valid[id] {
			return result, errors.New("daily egress alerts require collected host interface or vnstat sources")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	for _, src := range status.Sources {
		if !valid[src.SourceID] || len(wanted) > 0 && !wanted[src.SourceID] {
			continue
		}
		var up, down int64
		if err = tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(up),0),COALESCE(SUM(down),0) FROM metrics WHERE resolution='day' AND source_id=? AND bucket=?", src.SourceID, start.UnixMilli()).Scan(&up, &down); err != nil {
			return result, err
		}
		var tier int64
		for _, n := range thresholds {
			if up >= n*(1<<30) {
				tier = n
			}
		}
		if tier == 0 {
			continue
		}
		var previous int64
		if err = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(threshold),0) FROM alerts WHERE source_id=? AND day=?", src.SourceID, day).Scan(&previous); err != nil {
			return result, err
		}
		if tier <= previous {
			continue
		}
		h := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d", src.SourceID, day, tier)))
		a := Alert{ID: fmt.Sprintf("%x", h[:16]), SourceID: src.SourceID, Day: day, ThresholdGiB: tier, UploadBytes: up, DownloadBytes: down, CreatedAt: now.UTC(), State: "pending"}
		raw, _ := json.Marshal(a)
		// A newer unsent tier supersedes older queued tiers so reconnecting cannot flood.
		if _, err = tx.ExecContext(ctx, "UPDATE alerts SET state='superseded' WHERE source_id=? AND day=? AND state IN ('pending','failed')", src.SourceID, day); err != nil {
			return result, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO alerts(id,source_id,day,threshold,payload,state,created) VALUES(?,?,?,?,?,?,?)", a.ID, a.SourceID, a.Day, a.ThresholdGiB, raw, a.State, millis(a.CreatedAt)); err != nil {
			return result, err
		}
		result = append(result, a)
	}
	if err = tx.Commit(); err != nil {
		return result, storageError(err)
	}
	return result, nil
}
func (s *Store) Alerts(ctx context.Context, limit int) ([]Alert, error) {
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 1000 {
		return nil, errors.New("alert limit must be 1–1000")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT payload,state FROM alerts ORDER BY created DESC,id LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Alert{}
	for rows.Next() {
		var raw []byte
		var state string
		if err = rows.Scan(&raw, &state); err != nil {
			return nil, err
		}
		var a Alert
		if err = json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		a.State = state
		result = append(result, a)
	}
	return result, rows.Err()
}
func (s *Store) DeliverAlerts(ctx context.Context, c AlertConfig) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if !c.Enabled || c.WebhookFile == "" && c.WebhookEnv == "" {
		return nil
	}
	if s.readOnly {
		return ErrReadOnly
	}
	if err := validateAlerts(c); err != nil {
		return err
	}
	address, err := webhookAddress(c)
	if err != nil {
		return err
	}
	// A durable lease coordinates notifier processes. Never hold the ingest mutex
	// or a database transaction while waiting for the remote webhook.
	now := time.Now().UnixMilli()
	rows, err := s.db.QueryContext(ctx, "SELECT payload FROM alerts WHERE attempts<6 AND next_attempt<=? AND (state IN ('pending','failed') OR (state='sending' AND lease_until<?)) ORDER BY created,id LIMIT 4", now, now)
	if err != nil {
		return err
	}
	queue := []Alert{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var a Alert
		if err = json.Unmarshal(raw, &a); err != nil {
			rows.Close()
			return err
		}
		queue = append(queue, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, a := range queue {
		if a.Attempts >= 6 || time.Now().Before(a.NextAttempt) {
			continue
		}
		body, _ := json.Marshal(map[string]string{"content": fmt.Sprintf("lazyclash · %s daily host TX crossed %d GiB\n%s · observed TX %.2f GiB / RX %.2f GiB\nMeasured host traffic; not a billing amount or complete user attribution.", a.SourceID, a.ThresholdGiB, a.Day, float64(a.UploadBytes)/(1<<30), float64(a.DownloadBytes)/(1<<30))})
		request, x := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(body))
		if x != nil {
			return errors.New("cannot create alert request")
		}
		request.Header.Set("Content-Type", "application/json")
		a.Attempts++
		a.LastError = ""
		claimRaw, _ := json.Marshal(a)
		claim, claimErr := s.db.ExecContext(ctx, "UPDATE alerts SET state='sending',payload=?,attempts=?,lease_until=? WHERE id=? AND attempts<6 AND next_attempt<=? AND (state IN ('pending','failed') OR (state='sending' AND lease_until<?))", claimRaw, a.Attempts, time.Now().Add(2*time.Minute).UnixMilli(), a.ID, time.Now().UnixMilli(), time.Now().UnixMilli())
		if claimErr != nil {
			return claimErr
		}
		claimed, claimErr := claim.RowsAffected()
		if claimErr != nil {
			return claimErr
		}
		if claimed == 0 {
			continue
		}
		response, x := client.Do(request)
		if x != nil {
			a.State = "failed"
			a.LastError = "Notification transport failed; a timeout can leave delivery uncertain and a retry may duplicate it."
		} else {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				a.State = "sent"
			} else {
				a.State = "failed"
				a.LastError = fmt.Sprintf("Notification returned HTTP %d", response.StatusCode)
			}
		}
		if a.State == "failed" {
			a.NextAttempt = time.Now().Add(time.Duration(1<<min(a.Attempts-1, 6)) * time.Minute)
		} else {
			a.NextAttempt = time.Time{}
		}
		raw, _ := json.Marshal(a)
		if _, err = s.db.ExecContext(ctx, "UPDATE alerts SET payload=?,state=?,attempts=?,next_attempt=?,lease_until=0 WHERE id=?", raw, a.State, a.Attempts, millis(a.NextAttempt), a.ID); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}
func webhookAddress(c AlertConfig) (string, error) {
	var address string
	if c.WebhookEnv != "" {
		address = os.Getenv(c.WebhookEnv)
	} else {
		st, err := os.Lstat(c.WebhookFile)
		if err != nil || !st.Mode().IsRegular() || st.Size() > 16384 || st.Mode().Perm()&0077 != 0 {
			return "", errors.New("alert webhook file must be a private regular file no larger than 16 KiB")
		}
		b, err := os.ReadFile(c.WebhookFile)
		if err != nil {
			return "", errors.New("cannot read alert webhook reference")
		}
		address = strings.TrimSpace(string(b))
	}
	u, err := url.Parse(address)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(address, "\r\n\x00") {
		return "", errors.New("alert webhook reference does not contain a valid URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !(u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
			return "", errors.New("alert webhook must use HTTPS (HTTP is allowed only on loopback)")
		}
	}
	return address, nil
}
