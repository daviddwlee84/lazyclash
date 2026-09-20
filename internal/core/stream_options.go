package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// StreamOptions optionally bounds collection. Zero values leave the stream
// unlimited. Duration starts after successful response headers; Limit counts
// only records that consume reports as successfully emitted.
type StreamOptions struct {
	Duration time.Duration
	Limit    int
}

var errStreamDuration = errors.New("stream collection duration reached")

// StreamWithOptions consumes newline-delimited objects without reconnecting.
// consume returns whether it emitted the record, or an output error. Reaching
// either bound is success; disconnects and caller cancellation remain errors.
func (c *Client) StreamWithOptions(ctx context.Context, resource string, query url.Values, options StreamOptions, consume func(Object) (bool, error)) error {
	const op = "stream controller events"
	if !slices.Contains([]string{"logs", "traffic", "memory"}, resource) || consume == nil || options.Duration < 0 || options.Limit < 0 {
		return &Error{Kind: KindInvalid, Operation: op}
	}
	streamCtx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	resp, cancel, err := c.request(streamCtx, http.MethodGet, []string{resource}, query, nil, false, true, op)
	if err != nil {
		return err
	}
	defer cancel()
	defer resp.Body.Close()
	if options.Duration > 0 {
		timer := time.AfterFunc(options.Duration, func() { stop(errStreamDuration) })
		defer timer.Stop()
	}
	canceled := func() error {
		return &Error{Kind: KindCanceled, Operation: op, cause: ctx.Err()}
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 16<<10), maxStreamLineBytes)
	emitted := 0
	for scanner.Scan() {
		if ctx.Err() != nil {
			return canceled()
		}
		if errors.Is(context.Cause(streamCtx), errStreamDuration) {
			return nil
		}
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var object Object
		if err := json.Unmarshal(scanner.Bytes(), &object); err != nil || object == nil {
			return &Error{Kind: KindInvalid, Operation: op}
		}
		written, err := consume(object)
		if err != nil {
			// A failed output must not become success even if a bound elapsed
			// while the writer was running.
			return err
		}
		if ctx.Err() != nil {
			return canceled()
		}
		if written {
			emitted++
			if options.Limit > 0 && emitted >= options.Limit {
				return nil
			}
		}
	}
	if ctx.Err() != nil {
		return canceled()
	}
	// Only our own cancellation of a body read counts as bounded completion.
	// EOF and unrelated read failures remain errors, even near the timer edge.
	if errors.Is(context.Cause(streamCtx), errStreamDuration) &&
		(errors.Is(scanner.Err(), errStreamDuration) || errors.Is(scanner.Err(), context.Canceled)) {
		return nil
	}
	return &Error{Kind: KindUnreachable, Operation: op}
}
