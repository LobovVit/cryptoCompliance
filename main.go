package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed web/*
var assets embed.FS

type contextKey string

const userKey contextKey = "user"

type App struct {
	store        *PGStore
	aml          AMLProvider
	secureCookie bool
	allowedHost  string
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, code int, msg string) {
	reply(w, code, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, 400, "Некорректный JSON или слишком большой запрос")
		return false
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		fail(w, 400, "Ожидается один JSON объект")
		return false
	}
	return true
}
func userFrom(r *http.Request) User { return r.Context().Value(userKey).(User) }
func (a *App) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("cc_session")
		if err != nil {
			fail(w, 401, "Требуется вход")
			return
		}
		u, csrf, err := a.store.session(r.Context(), c.Value)
		if err != nil {
			fail(w, 401, "Сессия истекла")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("X-CSRF-Token") != csrf {
			fail(w, 403, "Некорректный CSRF-токен")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}
func requireWrite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !canWrite(userFrom(r).Role) {
			fail(w, 403, "Недостаточно прав")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func requireOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r).Role != "owner" {
			fail(w, 403, "Требуются права владельца")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", a.login)
	mux.Handle("GET /api/auth/me", a.auth(http.HandlerFunc(a.me)))
	mux.Handle("POST /api/auth/logout", a.auth(http.HandlerFunc(a.logout)))
	mux.Handle("GET /api/users", a.auth(requireOwner(http.HandlerFunc(a.listUsers))))
	mux.Handle("POST /api/users", a.auth(requireOwner(http.HandlerFunc(a.createUser))))
	mux.Handle("GET /api/deals", a.auth(http.HandlerFunc(a.listDeals)))
	mux.Handle("POST /api/deals", a.auth(requireWrite(http.HandlerFunc(a.createDeal))))
	mux.Handle("PUT /api/deals/{id}/checks/{key}", a.auth(requireWrite(http.HandlerFunc(a.updateCheck))))
	mux.Handle("POST /api/deals/{id}/screenings", a.auth(requireWrite(http.HandlerFunc(a.screen))))
	mux.Handle("GET /api/deals/{id}/report", a.auth(http.HandlerFunc(a.report)))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "Маршрут не найден") })
	static, _ := fs.Sub(assets, "web")
	mux.Handle("/", http.FileServer(http.FS(static)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if a.allowedHost != "" && r.Host != a.allowedHost {
			fail(w, 403, "Недопустимый Host")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			origin := r.Header.Get("Origin")
			scheme := "http"
			if a.secureCookie {
				scheme = "https"
			}
			if origin != "" && origin != scheme+"://"+r.Host {
				fail(w, 403, "Недопустимый Origin")
				return
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				fail(w, 415, "Требуется application/json")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	token, csrf := randomToken(), randomToken()
	u, err := a.store.login(r.Context(), normalizeEmail(body.Email), body.Password, token, csrf)
	if err != nil {
		time.Sleep(200 * time.Millisecond)
		fail(w, 401, "Неверный email или пароль")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "cc_session", Value: token, Path: "/", MaxAge: 43200, HttpOnly: true, Secure: a.secureCookie, SameSite: http.SameSiteStrictMode})
	reply(w, 200, map[string]any{"user": u, "csrfToken": csrf, "amlConfigured": a.aml.Configured(), "amlProvider": a.aml.Name()})
}
func (a *App) me(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	c, _ := r.Cookie("cc_session")
	_, csrf, _ := a.store.session(r.Context(), c.Value)
	reply(w, 200, map[string]any{"user": u, "csrfToken": csrf, "amlConfigured": a.aml.Configured(), "amlProvider": a.aml.Name()})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("cc_session")
	_ = a.store.logout(r.Context(), c.Value)
	http.SetCookie(w, &http.Cookie{Name: "cc_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secureCookie, SameSite: http.SameSiteStrictMode})
	reply(w, 200, map[string]bool{"ok": true})
}
func (a *App) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.store.listUsers(r.Context(), userFrom(r))
	if err != nil {
		fail(w, 500, "Не удалось загрузить пользователей")
		return
	}
	reply(w, 200, users)
}
func (a *App) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &body) {
		return
	}
	u, err := a.store.createUser(r.Context(), userFrom(r), body.Email, body.Name, body.Password, body.Role)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			fail(w, 409, "Пользователь с таким email уже существует")
			return
		}
		fail(w, 400, err.Error())
		return
	}
	reply(w, 201, u)
}
func (a *App) listDeals(w http.ResponseWriter, r *http.Request) {
	ds, err := a.store.listDeals(r.Context(), userFrom(r))
	if err != nil {
		log.Printf("list deals: %v", err)
		fail(w, 500, "Не удалось загрузить сделки")
		return
	}
	reply(w, 200, ds)
}
func (a *App) createDeal(w http.ResponseWriter, r *http.Request) {
	var d Deal
	if !decode(w, r, &d) {
		return
	}
	if err := validateDeal(d); err != nil {
		fail(w, 400, err.Error())
		return
	}
	d, err := a.store.createDeal(r.Context(), userFrom(r), d)
	if err != nil {
		log.Printf("create deal: %v", err)
		fail(w, 500, "Не удалось сохранить сделку")
		return
	}
	reply(w, 201, d)
}
func (a *App) updateCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version  int    `json:"version"`
		Status   string `json:"status"`
		Evidence string `json:"evidence"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Status != "pending" && body.Status != "verified" && body.Status != "flagged" {
		fail(w, 400, "Неизвестный результат проверки")
		return
	}
	if strings.TrimSpace(body.Evidence) == "" || len(body.Evidence) > 8000 {
		fail(w, 400, "Укажите основание (до 8000 байт)")
		return
	}
	d, err := a.store.updateCheck(r.Context(), userFrom(r), r.PathValue("id"), r.PathValue("key"), body.Version, body.Status, body.Evidence)
	if errors.Is(err, errConflict) {
		fail(w, 409, "Досье изменено. Откройте его повторно")
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 404, "Сделка или проверка не найдена")
		return
	}
	if err != nil {
		log.Printf("update check: %v", err)
		fail(w, 500, "Не удалось сохранить проверку")
		return
	}
	reply(w, 200, d)
}
func (a *App) screen(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	d, err := a.store.getDeal(r.Context(), u.OrganizationID, r.PathValue("id"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 404, "Сделка не найдена")
		return
	}
	if err != nil {
		fail(w, 500, "Не удалось загрузить сделку")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result, screenErr := a.aml.ScreenAddress(ctx, d.Network, d.Wallet)
	sc, saveErr := a.store.saveScreening(r.Context(), u, d, a.aml.Name(), result, screenErr)
	if saveErr != nil {
		log.Printf("save screening: %v", saveErr)
		fail(w, 500, "Не удалось сохранить результат провайдера")
		return
	}
	if screenErr != nil {
		reply(w, 503, sc)
		return
	}
	reply(w, 200, sc)
}
func (a *App) report(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	d, err := a.store.getDeal(r.Context(), u.OrganizationID, r.PathValue("id"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 404, "Сделка не найдена")
		return
	}
	if err != nil {
		fail(w, 500, "Не удалось сформировать отчёт")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="dossier-`+d.ID+`.json"`)
	reply(w, 200, map[string]any{"generatedAt": iso(time.Now()), "scope": "Рабочее досье. Результат провайдера не является автоматическим разрешением платежа или юридическим заключением.", "organization": u.Organization, "deal": d})
}

func main() {
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL обязателен")
	}
	store, err := openPG(ctx, dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer store.close()
	if err = store.migrate(ctx); err != nil {
		log.Fatal(err)
	}
	org := os.Getenv("ADMIN_ORG")
	if org == "" {
		org = "Демо-компания"
	}
	name := os.Getenv("ADMIN_NAME")
	if name == "" {
		name = "Владелец"
	}
	if err = store.bootstrap(ctx, org, os.Getenv("ADMIN_EMAIL"), name, os.Getenv("ADMIN_PASSWORD")); err != nil {
		log.Fatal(err)
	}
	store.cleanupSessions(ctx)
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	allowedHost := os.Getenv("ALLOWED_HOST")
	if allowedHost == "" {
		allowedHost = addr
	}
	app := &App{store: store, aml: newChainalysis(os.Getenv("CHAINALYSIS_API_KEY"), os.Getenv("CHAINALYSIS_BASE_URL")), secureCookie: os.Getenv("COOKIE_SECURE") == "true", allowedHost: allowedHost}
	server := &http.Server{Addr: addr, Handler: app.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("Сервис: http://%s; AML: %s (configured=%t)", addr, app.aml.Name(), app.aml.Configured())
	log.Fatal(server.ListenAndServe())
}
