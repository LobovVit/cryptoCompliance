package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

//go:embed schema.sql
var schemaFS embed.FS
var errConflict = errors.New("conflict")

type PGStore struct{ pool *pgxpool.Pool }

func openPG(ctx context.Context, url string) (*PGStore, error) {
	p, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return &PGStore{p}, nil
}
func (s *PGStore) close() { s.pool.Close() }
func (s *PGStore) migrate(ctx context.Context) error {
	b, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, string(b))
	return err
}

func (s *PGStore) bootstrap(ctx context.Context, org, email, name, password string) error {
	if email == "" || password == "" {
		return errors.New("ADMIN_EMAIL и ADMIN_PASSWORD обязательны")
	}
	if len(password) < 12 {
		return errors.New("ADMIN_PASSWORD должен содержать минимум 12 символов")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var count int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	var oid string
	if err = tx.QueryRow(ctx, "INSERT INTO organizations(name) VALUES($1) RETURNING id", org).Scan(&oid); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO users(organization_id,email,display_name,password_hash,role) VALUES($1,lower($2),$3,$4,'owner')", oid, email, name, string(hash))
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func tokenHash(token string) []byte { h := sha256.Sum256([]byte(token)); return h[:] }
func (s *PGStore) login(ctx context.Context, email, password, token, csrf string) (User, error) {
	var u User
	var hash string
	err := s.pool.QueryRow(ctx, `SELECT u.id,u.organization_id,o.name,u.email,u.display_name,u.role,u.password_hash FROM users u JOIN organizations o ON o.id=u.organization_id WHERE lower(u.email)=lower($1) AND u.active`, email).Scan(&u.ID, &u.OrganizationID, &u.Organization, &u.Email, &u.Name, &u.Role, &hash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return User{}, errors.New("неверный email или пароль")
	}
	_, err = s.pool.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES($1,$2,$3,now()+interval '12 hours')", tokenHash(token), u.ID, csrf)
	return u, err
}
func (s *PGStore) session(ctx context.Context, token string) (User, string, error) {
	var u User
	var csrf string
	err := s.pool.QueryRow(ctx, `SELECT u.id,u.organization_id,o.name,u.email,u.display_name,u.role,s.csrf_token FROM sessions s JOIN users u ON u.id=s.user_id JOIN organizations o ON o.id=u.organization_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active`, tokenHash(token)).Scan(&u.ID, &u.OrganizationID, &u.Organization, &u.Email, &u.Name, &u.Role, &csrf)
	return u, csrf, err
}
func (s *PGStore) logout(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM sessions WHERE token_hash=$1", tokenHash(token))
	return err
}
func (s *PGStore) cleanupSessions(ctx context.Context) {
	s.pool.Exec(ctx, "DELETE FROM sessions WHERE expires_at<=now()")
}

func (s *PGStore) listUsers(ctx context.Context, u User) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,organization_id,email,display_name,role FROM users WHERE organization_id=$1 ORDER BY created_at`, u.OrganizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var item User
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Email, &item.Name, &item.Role); err != nil {
			return nil, err
		}
		item.Organization = u.Organization
		out = append(out, item)
	}
	return out, rows.Err()
}
func (s *PGStore) createUser(ctx context.Context, owner User, email, name, password, role string) (User, error) {
	if role != "owner" && role != "compliance" && role != "viewer" {
		return User{}, errors.New("неизвестная роль")
	}
	if len(password) < 12 {
		return User{}, errors.New("пароль должен содержать минимум 12 символов")
	}
	if strings.TrimSpace(name) == "" || len(name) > 200 {
		return User{}, errors.New("укажите имя до 200 символов")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return User{}, err
	}
	u := User{OrganizationID: owner.OrganizationID, Organization: owner.Organization, Email: normalizeEmail(email), Name: name, Role: role}
	err = s.pool.QueryRow(ctx, `INSERT INTO users(organization_id,email,display_name,password_hash,role) VALUES($1,$2,$3,$4,$5) RETURNING id`, u.OrganizationID, u.Email, u.Name, string(hash), u.Role).Scan(&u.ID)
	return u, err
}

func (s *PGStore) listDeals(ctx context.Context, u User) ([]Deal, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,version,status,company,counterparty,country,registration,beneficiary,contract,direction,purpose,amount::text,asset,network,wallet,operator,created_at FROM deals WHERE organization_id=$1 ORDER BY created_at DESC`, u.OrganizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Deal{}
	for rows.Next() {
		var d Deal
		var created time.Time
		if err = rows.Scan(&d.ID, &d.Version, &d.Status, &d.Company, &d.Counterparty, &d.Country, &d.Registration, &d.Beneficiary, &d.Contract, &d.Direction, &d.Purpose, &d.Amount, &d.Asset, &d.Network, &d.Wallet, &d.Operator, &created); err != nil {
			return nil, err
		}
		d.CreatedAt = iso(created)
		if err = s.loadParts(ctx, u.OrganizationID, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *PGStore) getDeal(ctx context.Context, org, id string) (Deal, error) {
	var d Deal
	var created time.Time
	err := s.pool.QueryRow(ctx, `SELECT id,version,status,company,counterparty,country,registration,beneficiary,contract,direction,purpose,amount::text,asset,network,wallet,operator,created_at FROM deals WHERE organization_id=$1 AND id=$2`, org, id).Scan(&d.ID, &d.Version, &d.Status, &d.Company, &d.Counterparty, &d.Country, &d.Registration, &d.Beneficiary, &d.Contract, &d.Direction, &d.Purpose, &d.Amount, &d.Asset, &d.Network, &d.Wallet, &d.Operator, &created)
	if err != nil {
		return d, err
	}
	d.CreatedAt = iso(created)
	err = s.loadParts(ctx, org, &d)
	return d, err
}
func (s *PGStore) loadParts(ctx context.Context, org string, d *Deal) error {
	d.Checks = []Check{}
	rows, err := s.pool.Query(ctx, `SELECT key,status,evidence,reviewer_name,updated_at FROM deal_checks WHERE organization_id=$1 AND deal_id=$2 ORDER BY key`, org, d.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var c Check
		var t *time.Time
		if err = rows.Scan(&c.Key, &c.Status, &c.Evidence, &c.Reviewer, &t); err != nil {
			rows.Close()
			return err
		}
		if t != nil {
			c.UpdatedAt = iso(*t)
		}
		d.Checks = append(d.Checks, c)
	}
	rows.Close()
	d.Events = []Event{}
	rows, err = s.pool.Query(ctx, `SELECT created_at,action,actor_name,detail FROM audit_events WHERE organization_id=$1 AND deal_id=$2 ORDER BY id`, org, d.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var e Event
		var t time.Time
		if err = rows.Scan(&t, &e.Action, &e.Actor, &e.Detail); err != nil {
			rows.Close()
			return err
		}
		e.At = iso(t)
		d.Events = append(d.Events, e)
	}
	rows.Close()
	d.Screenings = []Screening{}
	rows, err = s.pool.Query(ctx, `SELECT id,provider,subject,status,response_hash,error_message,created_at,COALESCE(jsonb_array_length(response_json->'identifications'),0) FROM screening_runs WHERE organization_id=$1 AND deal_id=$2 ORDER BY created_at DESC`, org, d.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var a Screening
		var t time.Time
		if err = rows.Scan(&a.ID, &a.Provider, &a.Subject, &a.Status, &a.ResponseHash, &a.Error, &t, &a.Matches); err != nil {
			rows.Close()
			return err
		}
		a.CreatedAt = iso(t)
		d.Screenings = append(d.Screenings, a)
	}
	rows.Close()
	return rows.Err()
}
func (s *PGStore) createDeal(ctx context.Context, u User, d Deal) (Deal, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return d, err
	}
	defer tx.Rollback(ctx)
	var created time.Time
	err = tx.QueryRow(ctx, `INSERT INTO deals(organization_id,company,counterparty,country,registration,beneficiary,contract,direction,purpose,amount,asset,network,wallet,operator,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id,created_at`, u.OrganizationID, d.Company, d.Counterparty, d.Country, d.Registration, d.Beneficiary, d.Contract, d.Direction, d.Purpose, d.Amount, d.Asset, d.Network, d.Wallet, d.Operator, u.ID).Scan(&d.ID, &created)
	if err != nil {
		return d, err
	}
	d.CreatedAt = iso(created)
	for _, k := range checkNames {
		if _, err = tx.Exec(ctx, "INSERT INTO deal_checks(organization_id,deal_id,key) VALUES($1,$2,$3)", u.OrganizationID, d.ID, k); err != nil {
			return d, err
		}
	}
	_, err = tx.Exec(ctx, "INSERT INTO audit_events(organization_id,deal_id,actor_id,actor_name,action,detail) VALUES($1,$2,$3,$4,'created','Создано досье сделки')", u.OrganizationID, d.ID, u.ID, u.Name)
	if err != nil {
		return d, err
	}
	if err = tx.Commit(ctx); err != nil {
		return d, err
	}
	return s.getDeal(ctx, u.OrganizationID, d.ID)
}
func (s *PGStore) updateCheck(ctx context.Context, u User, id, key string, version int, status, evidence string) (Deal, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Deal{}, err
	}
	defer tx.Rollback(ctx)
	var actual int
	if err = tx.QueryRow(ctx, "SELECT version FROM deals WHERE organization_id=$1 AND id=$2 FOR UPDATE", u.OrganizationID, id).Scan(&actual); err != nil {
		return Deal{}, err
	}
	if actual != version {
		return Deal{}, errConflict
	}
	ct, err := tx.Exec(ctx, `UPDATE deal_checks SET status=$1,evidence=$2,reviewer_id=$3,reviewer_name=$4,updated_at=now() WHERE organization_id=$5 AND deal_id=$6 AND key=$7`, status, evidence, u.ID, u.Name, u.OrganizationID, id, key)
	if err != nil {
		return Deal{}, err
	}
	if ct.RowsAffected() != 1 {
		return Deal{}, pgx.ErrNoRows
	}
	rows, err := tx.Query(ctx, "SELECT key,status,evidence,reviewer_name,updated_at FROM deal_checks WHERE organization_id=$1 AND deal_id=$2", u.OrganizationID, id)
	if err != nil {
		return Deal{}, err
	}
	cs := []Check{}
	for rows.Next() {
		var c Check
		var t *time.Time
		if err = rows.Scan(&c.Key, &c.Status, &c.Evidence, &c.Reviewer, &t); err != nil {
			rows.Close()
			return Deal{}, err
		}
		cs = append(cs, c)
	}
	rows.Close()
	next := dealStatus(cs)
	ct, err = tx.Exec(ctx, "UPDATE deals SET status=$1,version=version+1 WHERE organization_id=$2 AND id=$3 AND version=$4", next, u.OrganizationID, id, version)
	if err != nil {
		return Deal{}, err
	}
	if ct.RowsAffected() != 1 {
		return Deal{}, errConflict
	}
	detail := fmt.Sprintf("%s → %s. %s", key, status, evidence)
	_, err = tx.Exec(ctx, "INSERT INTO audit_events(organization_id,deal_id,actor_id,actor_name,action,detail) VALUES($1,$2,$3,$4,'check_updated',$5)", u.OrganizationID, id, u.ID, u.Name, detail)
	if err != nil {
		return Deal{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Deal{}, err
	}
	return s.getDeal(ctx, u.OrganizationID, id)
}
func (s *PGStore) saveScreening(ctx context.Context, u User, d Deal, p string, res AMLResult, screenErr error) (Screening, error) {
	status := "error"
	msg := ""
	raw := res.Raw
	if screenErr != nil {
		msg = screenErr.Error()
		if len(raw) == 0 {
			raw = []byte(msg)
		}
	} else {
		status = res.Status
	}
	hash := res.Hash
	if hash == "" {
		sum := sha256.Sum256(raw)
		hash = hex.EncodeToString(sum[:])
	}
	var payload any
	if json.Valid(raw) {
		payload = string(raw)
	}
	var sc Screening
	var t time.Time
	err := s.pool.QueryRow(ctx, `INSERT INTO screening_runs(organization_id,deal_id,provider,subject,status,response_hash,response_json,error_message,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9) RETURNING id,created_at`, u.OrganizationID, d.ID, p, d.Wallet, status, hash, payload, msg, u.ID).Scan(&sc.ID, &t)
	if err != nil {
		return sc, err
	}
	sc.Provider = p
	sc.Subject = d.Wallet
	sc.Status = status
	sc.ResponseHash = hash
	sc.Error = msg
	sc.CreatedAt = iso(t)
	sc.Matches = res.Matches
	detail := fmt.Sprintf("%s: %s, совпадений: %d, hash: %s", p, status, res.Matches, hash)
	_, err = s.pool.Exec(ctx, "INSERT INTO audit_events(organization_id,deal_id,actor_id,actor_name,action,detail) VALUES($1,$2,$3,$4,'screening_run',$5)", u.OrganizationID, d.ID, u.ID, u.Name, detail)
	return sc, err
}
func normalizeEmail(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
