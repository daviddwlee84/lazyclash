package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestStreamDurationStartsAfterHeadersAndStopsQuietStream(t *testing.T) {
	const duration = 60 * time.Millisecond
	headersAt := make(chan time.Time, 1)
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(100 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		headersAt <- time.Now()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}, Options{Timeout: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := client.StreamWithOptions(ctx, "logs", nil, StreamOptions{Duration: duration}, func(Object) (bool, error) {
		t.Error("quiet stream produced an event")
		return true, nil
	})
	if err != nil {
		t.Fatalf("quiet bounded stream: %v", err)
	}
	select {
	case started := <-headersAt:
		if elapsed := time.Since(started); elapsed < duration {
			t.Fatalf("collection included connection time: elapsed %s, want at least %s after headers", elapsed, duration)
		}
	default:
		t.Fatal("stream stopped before successful headers")
	}
}

func TestStreamDurationDoesNotReplaceEstablishmentTimeout(t *testing.T) {
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}, Options{Timeout: 30 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.StreamWithOptions(ctx, "logs", nil, StreamOptions{Duration: 5 * time.Millisecond}, func(Object) (bool, error) { return true, nil })
	requireKind(t, err, KindUnreachable)
	if ctx.Err() != nil {
		t.Fatal("header timeout was not enforced")
	}
}

func TestStreamLimitCountsEmittedRecordsAndStopsBeforeBufferedFailure(t *testing.T) {
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{\"payload\":\"skip\"}\n{\"payload\":\"first\"}\n{\"payload\":\"skip\"}\n{\"payload\":\"second\"}\nnot-json\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}, Options{})
	var emitted []string
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.StreamWithOptions(ctx, "logs", nil, StreamOptions{Duration: time.Second, Limit: 2}, func(object Object) (bool, error) {
		payload := object["payload"].(string)
		if payload == "skip" {
			return false, nil
		}
		emitted = append(emitted, payload)
		return true, nil
	})
	if err != nil || len(emitted) != 2 || emitted[0] != "first" || emitted[1] != "second" {
		t.Fatalf("emitted = %v, error = %v", emitted, err)
	}
}

func TestStreamDurationWinsBeforeLimit(t *testing.T) {
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Object{"payload": "only one"})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	count := 0
	err := client.StreamWithOptions(ctx, "logs", nil, StreamOptions{Duration: 30 * time.Millisecond, Limit: 2}, func(Object) (bool, error) {
		count++
		return true, nil
	})
	if err != nil || count != 1 {
		t.Fatalf("duration before limit: count %d, error %v", count, err)
	}
}

func TestStreamBoundsDoNotHideFailures(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		kind    ErrorKind
	}{
		{"auth", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }, KindAuth},
		{"disconnect", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }, KindUnreachable},
		{"invalid", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "not-json\n") }, KindInvalid},
		{"read failure", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "999")
			_, _ = io.WriteString(w, " ")
		}, KindUnreachable},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fakeClient(t, test.handler, Options{})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := client.StreamWithOptions(ctx, "logs", nil, StreamOptions{Duration: 300 * time.Millisecond, Limit: 1}, func(Object) (bool, error) { return true, nil })
			requireKind(t, err, test.kind)
		})
	}
}

func TestStreamOutputFailureWinsAfterDuration(t *testing.T) {
	requestDone := make(chan struct{})
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Object{"payload": "one"})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(requestDone)
	}, Options{})
	failure := errors.New("output closed")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.StreamWithOptions(ctx, "logs", nil, StreamOptions{Duration: 30 * time.Millisecond, Limit: 1}, func(Object) (bool, error) {
		<-requestDone // The duration elapsed while the output was in progress.
		return false, failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("output failure became bounded success: %v", err)
	}
}

func TestStreamCallerCancellationWinsLimit(t *testing.T) {
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Object{"payload": "one"})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := client.StreamWithOptions(ctx, "logs", nil, StreamOptions{Duration: time.Second, Limit: 1}, func(Object) (bool, error) {
		cancel()
		return true, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation became bounded success: %v", err)
	}
}

func TestStreamCallerCancellationWinsElapsedDuration(t *testing.T) {
	requestDone := make(chan struct{})
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Object{"payload": "one"})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(requestDone)
	}, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.StreamWithOptions(ctx, "logs", nil, StreamOptions{Duration: 30 * time.Millisecond}, func(Object) (bool, error) {
		<-requestDone // The stream's own timer canceled the request first.
		cancel()
		return true, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("elapsed duration hid caller cancellation: %v", err)
	}
}

func TestStreamRejectsInvalidBoundsBeforeRequest(t *testing.T) {
	var requests atomic.Int32
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }, Options{})
	for _, options := range []StreamOptions{{Duration: -time.Second}, {Limit: -1}} {
		err := client.StreamWithOptions(context.Background(), "logs", nil, options, func(Object) (bool, error) { return true, nil })
		requireKind(t, err, KindInvalid)
	}
	if requests.Load() != 0 {
		t.Fatal("invalid bounds opened a stream")
	}
}
