package openrouter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JoyousJohn/scoria/internal/analyzer"
)

func testPayload() analyzer.Payload {
	return analyzer.Payload{
		Version: analyzer.PayloadVersion,
		Candidates: []analyzer.Candidate{
			{ID: "c1", Rule: "junk-dir", Title: "Generated directory: node_modules", Detail: "Generated output.", Confidence: "medium", Priority: 80, Items: 10, Bytes: 2 << 20, SizeBucket: "1-10 MiB"},
			{ID: "c2", Rule: "old-file", Title: "Old file", Detail: "Old metadata.", Confidence: "low", Priority: 20, Items: 1, Bytes: 1 << 20, SizeBucket: "1-10 MiB"},
		},
	}
}

func TestAnalyzeSendsRedactedPayloadAndValidates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("X-Title"); got != "Scoria" {
			t.Errorf("X-Title = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `C:\\`) || strings.Contains(string(body), "secret") {
			t.Errorf("request leaked a path: %s", body)
		}
		var request chatRequest
		if err := json.Unmarshal(body, &request); err != nil {
			t.Fatal(err)
		}
		if request.Model != "openai/test" {
			t.Errorf("model = %q", request.Model)
		}
		if len(request.Messages) != 2 {
			t.Fatalf("messages = %d", len(request.Messages))
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"findings\":[{\"id\":\"c2\",\"rank\":1,\"explanation\":\"Second\"},{\"id\":\"c1\",\"rank\":2,\"explanation\":\"First\"}]}"}}]}`)
	}))
	defer server.Close()

	client, err := New(Config{
		APIKey:  "test-key",
		Model:   "openai/test",
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Analyze(context.Background(), testPayload())
	if err != nil {
		t.Fatal(err)
	}
	if result.Analyzer != "openai-compatible" || result.Model != "openai/test" {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Findings) != 2 || result.Findings[0].ID != "c2" || result.Findings[0].Rank != 1 {
		t.Fatalf("findings = %#v", result.Findings)
	}
}

func TestAnalyzeHandlesErrorsWithoutLeakingKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"message":"invalid key"}}`)
	}))
	defer server.Close()

	client, err := New(Config{APIKey: "test-key", Model: "openai/test", BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Analyze(context.Background(), testPayload())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "test-key") {
		t.Fatalf("error leaked key: %v", err)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error = %v", err)
	}
}

func TestAnalyzeRejectsUnknownAndMissingIDs(t *testing.T) {
	cases := []string{
		`{"findings":[{"id":"c3","rank":1,"explanation":"x"},{"id":"c1","rank":2,"explanation":"y"}]}`,
		`{"findings":[{"id":"c1","rank":1,"explanation":"x"}]}`,
		`{"findings":[{"id":"c1","rank":1,"explanation":""},{"id":"c2","rank":2,"explanation":"y"}]}`,
	}
	for _, content := range cases {
		t.Run(content, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := chatCompletion{}
				response.Choices = make([]struct {
					Message struct {
						Content string `json:"content"`
					} `json:"message"`
				}, 1)
				response.Choices[0].Message.Content = content
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			client, err := New(Config{APIKey: "test-key", Model: "openai/test", BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Analyze(context.Background(), testPayload()); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAnalyzeAcceptsCodeFence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := chatCompletion{}
		response.Choices = make([]struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}, 1)
		response.Choices[0].Message.Content = "```json\n{\"findings\":[{\"id\":\"c1\",\"rank\":1,\"explanation\":\"A\"},{\"id\":\"c2\",\"rank\":2,\"explanation\":\"B\"}]}\n```"
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(Config{APIKey: "test-key", Model: "openai/test", BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Analyze(context.Background(), testPayload()); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzeTimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	client, err := New(Config{APIKey: "test-key", Model: "openai/test", BaseURL: server.URL, Timeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Analyze(context.Background(), testPayload()); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestNewRejectsInsecureRemoteBaseURL(t *testing.T) {
	if _, err := New(Config{APIKey: "test-key", Model: "openai/test", BaseURL: "http://example.com"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestAnalyzerLabelFollowsBaseURL(t *testing.T) {
	openRouter, err := New(Config{APIKey: "test-key", Model: "openai/test"})
	if err != nil {
		t.Fatal(err)
	}
	if openRouter.Name() != "openrouter" {
		t.Fatalf("name = %q, want openrouter", openRouter.Name())
	}

	custom, err := New(Config{APIKey: "test-key", Model: "openai/test", BaseURL: "https://api.example.com/v1/"})
	if err != nil {
		t.Fatal(err)
	}
	if custom.Name() != "openai-compatible" {
		t.Fatalf("name = %q, want openai-compatible", custom.Name())
	}
}

func TestValidateBaseURL(t *testing.T) {
	for _, base := range []string{"", DefaultBaseURL, "https://api.example.com/v1", "http://127.0.0.1:11434/v1"} {
		if err := ValidateBaseURL(base); err != nil {
			t.Fatalf("ValidateBaseURL(%q): %v", base, err)
		}
	}
	for _, base := range []string{"http://example.com", "ftp://example.com", "https://"} {
		if err := ValidateBaseURL(base); err == nil {
			t.Fatalf("ValidateBaseURL(%q) should fail", base)
		}
	}
}

func TestKeyRequiredOnlyForNonLoopback(t *testing.T) {
	for _, base := range []string{"", DefaultBaseURL, "https://api.example.com/v1"} {
		if !KeyRequired(base) {
			t.Fatalf("KeyRequired(%q) = false, want true", base)
		}
	}
	if KeyRequired("http://localhost:11434/v1") {
		t.Fatal("loopback should not require a key")
	}
}

func TestNewAllowsKeylessLoopback(t *testing.T) {
	if _, err := New(Config{Model: "local", BaseURL: "http://127.0.0.1:11434/v1"}); err != nil {
		t.Fatalf("loopback without key: %v", err)
	}
	if _, err := New(Config{Model: "remote", BaseURL: "https://api.example.com/v1"}); err == nil {
		t.Fatal("remote endpoint without key should fail")
	}
}

func TestStripCodeFence(t *testing.T) {
	if got := stripCodeFence("```json\n{\"a\":1}\n```"); got != `{"a":1}` {
		t.Fatalf("got %q", got)
	}
}

func TestDiscoverSendsDiscoveryPayloadAndValidates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if !strings.Contains(string(body), "directory_names") {
			t.Errorf("missing discovery payload: %s", body)
		}
		response := chatCompletion{}
		response.Choices = make([]struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}, 1)
		response.Choices[0].Message.Content = `{"patterns":[{"kind":"dir-basename","name":"DerivedData","confidence":"medium","reason":"Xcode build cache"}]}`
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(Config{APIKey: "test-key", Model: "openai/test", BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	payload := analyzer.DiscoveryPayload{
		Version:        analyzer.DiscoveryVersion,
		DirectoryNames: []analyzer.DirectoryName{{Name: "DerivedData", Files: 2, Bytes: 300}},
	}
	result, err := client.Discover(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Patterns) != 1 || result.Patterns[0].Name != "DerivedData" || result.Patterns[0].Bytes != 300 {
		t.Fatalf("patterns = %#v", result.Patterns)
	}
}
