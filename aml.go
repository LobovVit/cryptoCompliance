package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AMLResult struct {
	Status  string
	Matches int
	Raw     []byte
	Hash    string
}
type AMLProvider interface {
	Name() string
	Configured() bool
	ScreenAddress(context.Context, string, string) (AMLResult, error)
}
type ChainalysisClient struct {
	BaseURL, APIKey string
	Client          *http.Client
}

func (c *ChainalysisClient) Name() string     { return "chainalysis-sanctions" }
func (c *ChainalysisClient) Configured() bool { return strings.TrimSpace(c.APIKey) != "" }
func (c *ChainalysisClient) ScreenAddress(ctx context.Context, network, address string) (AMLResult, error) {
	if !c.Configured() {
		return AMLResult{}, errors.New("CHAINALYSIS_API_KEY не настроен")
	}
	if strings.TrimSpace(address) == "" {
		return AMLResult{}, errors.New("в сделке не указан адрес кошелька")
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://public.chainalysis.com/api/v1/address"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+url.PathEscape(address), nil)
	if err != nil {
		return AMLResult{}, err
	}
	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return AMLResult{}, fmt.Errorf("Chainalysis недоступен: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return AMLResult{}, err
	}
	sum := sha256.Sum256(raw)
	result := AMLResult{Raw: raw, Hash: hex.EncodeToString(sum[:])}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return result, fmt.Errorf("Chainalysis вернул HTTP %d", resp.StatusCode)
	}
	var body struct {
		Identifications []json.RawMessage `json:"identifications"`
	}
	if err = json.Unmarshal(raw, &body); err != nil {
		return result, errors.New("Chainalysis вернул некорректный JSON")
	}
	result.Matches = len(body.Identifications)
	if result.Matches > 0 {
		result.Status = "match"
	} else {
		result.Status = "clear"
	}
	return result, nil
}
func newChainalysis(key, base string) *ChainalysisClient {
	return &ChainalysisClient{APIKey: key, BaseURL: base, Client: &http.Client{Timeout: 12 * time.Second}}
}
