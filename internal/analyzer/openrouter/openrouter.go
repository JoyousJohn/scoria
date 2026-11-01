package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JoyousJohn/scoria/internal/analyzer"
)

const (
	DefaultBaseURL = "https://openrouter.ai/api/v1"
	DefaultTimeout = 60 * time.Second
)

const systemPrompt = `You are the analysis layer for Scoria, a read-only disk scanner.

The JSON input is a redacted candidate payload. It contains opaque candidate IDs and
coarse attributes. It contains no paths, filenames, usernames, or drive roots.

Rank every candidate exactly once by likely storage benefit versus risk.

Return strict JSON only, with this shape:
{"findings":[{"id":"c1","rank":1,"explanation":"..."}]}

Rules:
- Use every candidate ID exactly once.
- Ranks must be unique integers from 1 to N.
- Do not invent IDs.
- Keep explanations concise, specific, and cautious.
- Never say a file is safe to delete. Say what it appears to be and what the user should verify.
- Do not mention paths that are not in the payload.`

const discoverySystemPrompt = `You are the discovery layer for Scoria, a read-only disk scanner.

The JSON input contains aggregate directory basenames, extension classes, scan totals,
and the rules already covered. It contains no paths, filenames, usernames, or roots.

Propose directory-name patterns that commonly indicate generated, cache, or build data
and are not already covered by existing_rules.

Return strict JSON only, with this shape:
{"patterns":[{"kind":"dir-basename","name":"DerivedData","confidence":"medium","reason":"..."}]}

Rules:
- Only use names that appear in directory_names.
- Do not invent names.
- Do not propose names already covered by existing_rules.
- Confidence must be low, medium, or high.
- Explain what the directory usually contains and what the user should verify.
- Never say a directory is safe to delete.
- Return at most 10 patterns.`

type Config struct {
	APIKey     string
	Model      string
	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
}

type Client struct {
	endpoint string
	model    string
	key      string
	http     *http.Client
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatCompletion struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type modelResponse struct {
	Findings []analyzer.Finding `json:"findings"`
}

type discoveryResponse struct {
	Patterns []analyzer.DiscoveryFinding `json:"patterns"`
}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("openrouter: API key is required")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, fmt.Errorf("openrouter: model is required")
	}

	base := cfg.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	base = strings.TrimRight(base, "/")
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("openrouter: invalid base URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("openrouter: base URL must be http or https")
	}
	if parsed.Scheme != "https" && !loopback(parsed.Hostname()) {
		return nil, fmt.Errorf("openrouter: refusing non-HTTPS base URL for a non-loopback host")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("openrouter: base URL has no host")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		httpClient = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return &Client{
		endpoint: base + "/chat/completions",
		model:    strings.TrimSpace(cfg.Model),
		key:      strings.TrimSpace(cfg.APIKey),
		http:     httpClient,
	}, nil
}

func (c *Client) Name() string {
	return "openrouter"
}

func (c *Client) Analyze(ctx context.Context, payload analyzer.Payload) (analyzer.Result, error) {
	if len(payload.Candidates) == 0 {
		return analyzer.Result{Analyzer: "openrouter", Model: c.model, Findings: []analyzer.Finding{}}, nil
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return analyzer.Result{}, fmt.Errorf("openrouter: encode payload: %w", err)
	}
	content, err := c.chat(ctx, systemPrompt, string(payloadJSON))
	if err != nil {
		return analyzer.Result{}, err
	}
	var response modelResponse
	if err := json.Unmarshal([]byte(content), &response); err != nil {
		return analyzer.Result{}, fmt.Errorf("openrouter: model response was not valid JSON")
	}
	return analyzer.Validate(payload, analyzer.Result{
		Analyzer: "openrouter",
		Model:    c.model,
		Findings: response.Findings,
	})
}

func (c *Client) Discover(ctx context.Context, payload analyzer.DiscoveryPayload) (analyzer.DiscoveryResult, error) {
	if len(payload.DirectoryNames) == 0 {
		return analyzer.DiscoveryResult{Analyzer: "openrouter", Model: c.model, Patterns: []analyzer.DiscoveryFinding{}}, nil
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return analyzer.DiscoveryResult{}, fmt.Errorf("openrouter: encode discovery payload: %w", err)
	}
	content, err := c.chat(ctx, discoverySystemPrompt, string(payloadJSON))
	if err != nil {
		return analyzer.DiscoveryResult{}, err
	}
	var response discoveryResponse
	if err := json.Unmarshal([]byte(content), &response); err != nil {
		return analyzer.DiscoveryResult{}, fmt.Errorf("openrouter: discovery response was not valid JSON")
	}
	return analyzer.ValidateDiscovery(payload, analyzer.DiscoveryResult{
		Analyzer: "openrouter",
		Model:    c.model,
		Patterns: response.Patterns,
	})
}

func (c *Client) chat(ctx context.Context, system, user string) (string, error) {
	requestBody, err := json.Marshal(chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	})
	if err != nil {
		return "", fmt.Errorf("openrouter: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return "", fmt.Errorf("openrouter: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "scoria")
	req.Header.Set("X-Title", "Scoria")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("openrouter: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", fmt.Errorf("openrouter: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", statusError(resp.StatusCode)
	}

	var completion chatCompletion
	if err := json.Unmarshal(body, &completion); err != nil {
		return "", fmt.Errorf("openrouter: invalid response JSON")
	}
	if completion.Error != nil {
		return "", fmt.Errorf("openrouter: provider returned an error")
	}
	if len(completion.Choices) == 0 {
		return "", fmt.Errorf("openrouter: response contained no choices")
	}
	content := stripCodeFence(strings.TrimSpace(completion.Choices[0].Message.Content))
	if content == "" {
		return "", fmt.Errorf("openrouter: response contained no content")
	}
	return content, nil
}

func statusError(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return fmt.Errorf("openrouter: request failed: invalid API key (401)")
	case http.StatusPaymentRequired:
		return fmt.Errorf("openrouter: request failed: insufficient credits (402)")
	case http.StatusTooManyRequests:
		return fmt.Errorf("openrouter: request failed: rate limited (429)")
	default:
		return fmt.Errorf("openrouter: request failed with status %d", status)
	}
}

func stripCodeFence(content string) string {
	if !strings.HasPrefix(content, "```") {
		return content
	}
	if newline := strings.IndexByte(content, '\n'); newline >= 0 {
		content = content[newline+1:]
	}
	if end := strings.LastIndex(content, "```"); end >= 0 {
		content = content[:end]
	}
	return strings.TrimSpace(content)
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
