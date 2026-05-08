// Package extractor is a thin Go HTTP client for the Python intent
// extractor service.
//
// The gateway calls Extract(prompt) once per unique prompt; results
// are cached in memory keyed by SHA-256(prompt) so a session of N tool
// calls only triggers one extraction.
//
// The cache is intentionally simple — bounded LRU, fixed size, no TTL.
// In a multi-replica deployment each replica has its own cache; that's
// fine because cache misses just mean an extra LLM call, not an
// authorization bypass. Persistent caching belongs in Redis (later).
package extractor

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ExtractedIntent mirrors the Python extractor's response.intent shape.
type ExtractedIntent struct {
	Summary        string   `json:"summary"`
	AllowedTools   []string `json:"allowed_tools"`
	ForbiddenTools []string `json:"forbidden_tools"`
	Confidence     float64  `json:"confidence"`
	Rationale      string   `json:"rationale,omitempty"`
}

// Allows reports whether the tool is permitted by the extracted intent.
//
// Logic: forbidden_tools wins over allowed_tools (deny is final). If
// allowed_tools is non-empty, the tool MUST be in it. If allowed_tools
// is empty, only the forbidden list is enforced (i.e. the LLM signaled
// "I don't know what's needed, just block destructive things").
func (i *ExtractedIntent) Allows(tool string) (ok bool, reason string) {
	for _, t := range i.ForbiddenTools {
		if t == tool {
			return false, "tool is in intent.forbidden_tools"
		}
	}
	if len(i.AllowedTools) == 0 {
		return true, "no allowed_tools specified, only forbidden enforced"
	}
	for _, t := range i.AllowedTools {
		if t == tool {
			return true, "tool is in intent.allowed_tools"
		}
	}
	return false, "tool not in intent.allowed_tools"
}

// extractRequest mirrors the service's ExtractRequest.
type extractRequest struct {
	Prompt  string `json:"prompt"`
	AgentID string `json:"agent_id,omitempty"`
}

// extractResponse mirrors the service's ExtractResponse.
type extractResponse struct {
	Intent    ExtractedIntent `json:"intent"`
	Model     string          `json:"model"`
	LatencyMS int64           `json:"latency_ms"`
}

// Client is the Go-side intent extractor client with an LRU cache.
type Client struct {
	BaseURL    string        // e.g. "http://extractor:8090"
	HTTPClient *http.Client  // overridable for tests; defaults to a 10s-timeout client
	Timeout    time.Duration // per-request timeout, default 10s

	cache *lru
}

// New constructs a Client. cacheSize=0 disables caching (every call
// hits the service). Sensible default for production is 1024.
func New(baseURL string, cacheSize int) *Client {
	c := &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Timeout:    10 * time.Second,
		cache:      newLRU(cacheSize),
	}
	return c
}

// Extract returns the structured intent for prompt. agentID is logged
// at the extractor service but does not influence cache key — the same
// prompt is the same intent regardless of who's asking.
//
// The first call for a unique prompt triggers an HTTP call; subsequent
// calls for the same prompt return the cached result.
func (c *Client) Extract(ctx context.Context, prompt, agentID string) (*ExtractedIntent, error) {
	if prompt == "" {
		return nil, errors.New("prompt is empty")
	}
	if c.BaseURL == "" {
		return nil, errors.New("extractor base URL is not configured")
	}

	key := promptKey(prompt)
	if cached, ok := c.cache.get(key); ok {
		return cached, nil
	}

	body, err := json.Marshal(extractRequest{Prompt: prompt, AgentID: agentID})
	if err != nil {
		return nil, err
	}

	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/v1/extract", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("extractor request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("extractor read: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("extractor returned %d: %s", resp.StatusCode, string(respBody))
	}

	var er extractResponse
	if err := json.Unmarshal(respBody, &er); err != nil {
		return nil, fmt.Errorf("extractor decode: %w", err)
	}

	c.cache.put(key, &er.Intent)
	return &er.Intent, nil
}

// promptKey is the cache key for a prompt.
func promptKey(prompt string) string {
	h := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(h[:])
}

// ----------------------------------------------------------------------
// Tiny LRU cache (in-memory, bounded). We avoid an external dep on
// purpose — this is ~30 lines and we can fold it into Redis later
// without changing the Client API.
// ----------------------------------------------------------------------

type lru struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List
	idx      map[string]*list.Element
}

type lruEntry struct {
	key   string
	value *ExtractedIntent
}

func newLRU(capacity int) *lru {
	if capacity < 0 {
		capacity = 0
	}
	return &lru{
		capacity: capacity,
		ll:       list.New(),
		idx:      make(map[string]*list.Element),
	}
}

func (c *lru) get(key string) (*ExtractedIntent, bool) {
	if c.capacity == 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.idx[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*lruEntry).value, true
	}
	return nil, false
}

func (c *lru) put(key string, value *ExtractedIntent) {
	if c.capacity == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.idx[key]; ok {
		el.Value.(*lruEntry).value = value
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruEntry{key: key, value: value})
	c.idx[key] = el
	if c.ll.Len() > c.capacity {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.idx, oldest.Value.(*lruEntry).key)
		}
	}
}
