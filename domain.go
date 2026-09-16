package main

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

var checkNames = []string{"kyb", "sanctions", "wallet", "funds", "legal", "documents"}

type User struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Organization   string `json:"organization"`
	Email          string `json:"email"`
	Name           string `json:"name"`
	Role           string `json:"role"`
}
type Check struct {
	Key       string `json:"key"`
	Status    string `json:"status"`
	Evidence  string `json:"evidence"`
	Reviewer  string `json:"reviewer"`
	UpdatedAt string `json:"updatedAt"`
}
type Event struct {
	At     string `json:"at"`
	Action string `json:"action"`
	Actor  string `json:"actor"`
	Detail string `json:"detail"`
}
type Screening struct {
	ID           string `json:"id"`
	Provider     string `json:"provider"`
	Subject      string `json:"subject"`
	Status       string `json:"status"`
	ResponseHash string `json:"responseHash"`
	Error        string `json:"error"`
	CreatedAt    string `json:"createdAt"`
	Matches      int    `json:"matches"`
}
type Deal struct {
	ID           string      `json:"id"`
	Version      int         `json:"version"`
	CreatedAt    string      `json:"createdAt"`
	Company      string      `json:"company"`
	Counterparty string      `json:"counterparty"`
	Country      string      `json:"country"`
	Registration string      `json:"registration"`
	Beneficiary  string      `json:"beneficiary"`
	Contract     string      `json:"contract"`
	Direction    string      `json:"direction"`
	Purpose      string      `json:"purpose"`
	Amount       string      `json:"amount"`
	Asset        string      `json:"asset"`
	Network      string      `json:"network"`
	Wallet       string      `json:"wallet"`
	Operator     string      `json:"operator"`
	Checks       []Check     `json:"checks"`
	Events       []Event     `json:"events"`
	Screenings   []Screening `json:"screenings"`
	Status       string      `json:"status"`
}

var amountRE = regexp.MustCompile(`^[0-9]{1,15}(\.[0-9]{1,8})?$`)

func validateDeal(d Deal) error {
	for _, v := range []string{d.Company, d.Counterparty, d.Country, d.Registration, d.Contract, d.Purpose} {
		if strings.TrimSpace(v) == "" {
			return errors.New("Заполните компанию, контрагента, страну, регистрационный номер, договор и предмет сделки")
		}
	}
	for _, v := range []string{d.Company, d.Counterparty, d.Country, d.Registration, d.Contract, d.Purpose, d.Beneficiary, d.Operator, d.Wallet} {
		if len(v) > 2000 {
			return errors.New("Поле превышает 2000 байт")
		}
	}
	if !amountRE.MatchString(d.Amount) || strings.Trim(d.Amount, "0.") == "" {
		return errors.New("Укажите положительную сумму: до 15 цифр и 8 знаков после точки")
	}
	if d.Direction != "import" && d.Direction != "export" {
		return errors.New("Некорректное направление")
	}
	if d.Asset != "USDT" && d.Asset != "USDC" && d.Asset != "BTC" && d.Asset != "ETH" {
		return errors.New("Неизвестный актив")
	}
	if d.Network != "Ethereum" && d.Network != "Tron" && d.Network != "Bitcoin" {
		return errors.New("Неизвестная сеть")
	}
	if (d.Asset == "BTC") != (d.Network == "Bitcoin") || d.Asset == "ETH" && d.Network != "Ethereum" || d.Asset == "USDC" && d.Network != "Ethereum" {
		return errors.New("Актив не соответствует выбранной сети")
	}
	return nil
}
func dealStatus(checks []Check) string {
	complete := len(checks) == len(checkNames)
	for _, c := range checks {
		if c.Status == "flagged" {
			return "attention"
		}
		if c.Status != "verified" {
			complete = false
		}
	}
	if complete {
		return "reviewed"
	}
	return "pending"
}
func iso(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
func canWrite(role string) bool { return role == "owner" || role == "compliance" }
