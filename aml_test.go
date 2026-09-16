package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(body string) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestChainalysisClient(t *testing.T) {
	var key string
	c := newChainalysis("secret", "https://provider.test")
	c.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		key = r.Header.Get("X-API-Key")
		return response(`{"identifications":[{"category":"sanctions"}]}`), nil
	})}
	res, err := c.ScreenAddress(context.Background(), "Ethereum", "0xabc")
	if err != nil || key != "secret" || res.Status != "match" || res.Matches != 1 || res.Hash == "" {
		t.Fatalf("result=%+v key=%q err=%v", res, key, err)
	}
}
func TestChainalysisUnavailableAndClear(t *testing.T) {
	c := newChainalysis("", "")
	if _, err := c.ScreenAddress(context.Background(), "Ethereum", "0xabc"); err == nil {
		t.Fatal("missing key accepted")
	}
	c = newChainalysis("key", "https://provider.test")
	c.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) { return response(`{"identifications":[]}`), nil })}
	res, err := c.ScreenAddress(context.Background(), "Ethereum", "0xabc")
	if err != nil || res.Status != "clear" {
		t.Fatalf("result=%+v err=%v", res, err)
	}
}
func TestValidationAndStatus(t *testing.T) {
	d := Deal{Company: "A", Counterparty: "B", Country: "C", Registration: "D", Contract: "E", Purpose: "F", Direction: "import", Amount: "1.00000001", Asset: "USDT", Network: "Tron"}
	if err := validateDeal(d); err != nil {
		t.Fatal(err)
	}
	d.Amount = "0"
	if validateDeal(d) == nil {
		t.Fatal("zero accepted")
	}
	cs := []Check{}
	for _, k := range checkNames {
		cs = append(cs, Check{Key: k, Status: "verified"})
	}
	if dealStatus(cs) != "reviewed" {
		t.Fatal("not reviewed")
	}
	cs[2].Status = "flagged"
	if dealStatus(cs) != "attention" {
		t.Fatal("flag not prioritized")
	}
}
