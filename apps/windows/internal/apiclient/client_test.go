package apiclient

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

func noBackoff(t *testing.T) {
	old := backoff
	backoff = func(int) time.Duration { return 0 }
	t.Cleanup(func() { backoff = old })
}

// fakeUploads is the resumable-upload half of the receiver. With dropFirst it
// stores the first chunk and then cuts the connection before answering — what
// a flaky uplink looks like to the client.
type fakeUploads struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	patches   int
	dropFirst bool
}

func (f *fakeUploads) register(m *http.ServeMux) {
	m.HandleFunc("POST /api/v1/uploads", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"upload_id":"up_1","received":0}`)
	})
	m.HandleFunc("PATCH /api/v1/uploads/{id}", func(w http.ResponseWriter, r *http.Request) {
		off, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.patches++
		if off != int64(f.buf.Len()) {
			n := f.buf.Len()
			f.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"offset tidak sesuai","received":`+strconv.Itoa(n)+`}`)
			return
		}
		f.buf.Write(body)
		n, drop := f.buf.Len(), f.dropFirst
		f.dropFirst = false
		f.mu.Unlock()
		if drop {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
			return
		}
		_, _ = io.WriteString(w, `{"received":`+strconv.Itoa(n)+`}`)
	})
	m.HandleFunc("GET /api/v1/uploads/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		n := f.buf.Len()
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"received":`+strconv.Itoa(n)+`}`)
	})
}

func TestUploadResumesAfterLostReply(t *testing.T) {
	noBackoff(t)
	f := &fakeUploads{dropFirst: true}
	m := http.NewServeMux()
	f.register(m)
	srv := httptest.NewServer(m)
	defer srv.Close()

	data := bytes.Repeat([]byte("0123456789abcdef"), (5<<20)/16) // 5 MiB -> 3 chunks
	id, err := New(srv.URL, false).uploadBytes(data)
	if err != nil {
		t.Fatalf("uploadBytes: %v", err)
	}
	if id != "up_1" {
		t.Fatalf("upload id = %q", id)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !bytes.Equal(f.buf.Bytes(), data) {
		t.Fatalf("server holds %d bytes, want %d identical bytes", f.buf.Len(), len(data))
	}
	// The lost reply is recovered through the status call, so no chunk is sent twice.
	if f.patches != 3 {
		t.Fatalf("PATCH count = %d, want 3", f.patches)
	}
}

func TestSubmitRetriesServerErrorButNotClientError(t *testing.T) {
	noBackoff(t)
	for _, tc := range []struct {
		name      string
		codes     []int
		wantCalls int
		wantErr   bool
	}{
		{"5xx then ok", []int{503, 200}, 2, false},
		{"4xx is final", []int{422, 200}, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			m := http.NewServeMux()
			m.HandleFunc("PUT /api/v1/signatures/{id}/document", func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if string(body) != "%PDF-test" {
					t.Errorf("attempt %d sent body %q", calls+1, body)
				}
				code := tc.codes[calls]
				calls++
				w.WriteHeader(code)
				if code == http.StatusOK {
					_, _ = io.WriteString(w, `{"status":"accepted"}`)
				} else {
					_, _ = io.WriteString(w, `{"error":"nope"}`)
				}
			})
			srv := httptest.NewServer(m)
			defer srv.Close()

			out, err := New(srv.URL, false).SubmitDocument("sig_1", []byte("%PDF-test"))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if calls != tc.wantCalls {
				t.Fatalf("PUT count = %d, want %d", calls, tc.wantCalls)
			}
			if !tc.wantErr && out["status"] != "accepted" {
				t.Fatalf("status = %v", out["status"])
			}
		})
	}
}
