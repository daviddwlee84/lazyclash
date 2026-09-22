package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApplyWindowsHostPathFromPOSIXController(t *testing.T) {
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			writes++
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["path"] != `C:\Users\David User\config.yaml` {
				t.Error("core host path changed", body)
			}
		}
		fmt.Fprint(w, `{"mode":"rule"}`)
	}))
	defer server.Close()
	client, err := New(Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.ApplyConfig(context.Background(), `C:\Users\David User\config.yaml`); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{`C:relative.yaml`, `C:\`, `\\?\C:\config.yaml`, `C:\config.yaml:secret`} {
		if _, err = client.ApplyConfig(context.Background(), p); err == nil {
			t.Fatal("invalid Windows host path accepted", p)
		}
	}
	if writes != 1 {
		t.Fatal("invalid path reached controller", writes)
	}
}
