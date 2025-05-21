package controllers

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/gophish/gophish/auth"
	"github.com/gophish/gophish/config"
	ctx "github.com/gophish/gophish/context"
	"github.com/gophish/gophish/controllers/api"
	log "github.com/gophish/gophish/logger"
	mid "github.com/gophish/gophish/middleware"
	"github.com/gophish/gophish/middleware/ratelimit"
	"github.com/gophish/gophish/models"
	"github.com/gophish/gophish/util"
	"github.com/gophish/gophish/worker"
	"github.com/gorilla/csrf"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/jordan-wright/unindexed"
)

// AdminServerOption defines functional options for configuring AdminServer.
type AdminServerOption func(*AdminServer)

// AdminServer represents the administrative HTTP server with routes,
// middleware, TLS, and worker management.
type AdminServer struct {
	server  *http.Server
	worker  worker.Worker
	config  config.AdminServer
	limiter *ratelimit.PostLimiter
}

// defaultTLSConfig applies a secure TLS configuration with modern ciphers
// and minimum TLS version 1.2.
var defaultTLSConfig = &tls.Config{
	PreferServerCipherSuites: true,
	CurvePreferences: []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
	},
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		// Backwards compatibility with legacy clients
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	},
}

// WithWorker allows injection of a custom background worker.
func WithWorker(w worker.Worker) AdminServerOption {
	return func(as *AdminServer) {
		as.worker = w
	}
}

// NewAdminServer constructs an AdminServer with configuration and optional
// functional options.
func NewAdminServer(cfg config.AdminServer, opts ...AdminServerOption) *AdminServer {
	wrk, _ := worker.New() // ideally handle error here if worker.New() fails
	srv := &http.Server{
		ReadTimeout: 10 * time.Second,
		Addr:        cfg.ListenURL,
	}
	limiter := ratelimit.NewPostLimiter()

	as := &AdminServer{
		worker:  wrk,
		server:  srv,
		limiter: limiter,
		config:  cfg,
	}
	for _, opt := range opts {
		opt(as)
	}
	as.registerRoutes()
	return as
}

// Start launches the server with TLS if configured, otherwise plain HTTP.
func (as *AdminServer) Start() {
	if as.worker != nil {
		go as.worker.Start()
	}

	if as.config.UseTLS {
		as.server.TLSConfig = defaultTLSConfig

		if err := util.CheckAndCreateSSL(as.config.CertPath, as.config.KeyPath); err != nil {
			log.Fatalf("SSL cert/key check failed: %v", err)
		}

		log.Infof("Starting admin server with TLS at https://%s", as.config.ListenURL)
		log.Fatal(as.server.ListenAndServeTLS(as.config.CertPath, as.config.KeyPath))
		return
	}

	log.Infof("Starting admin server without TLS at http://%s", as.config.ListenURL)
	log.Fatal(as.server.ListenAndServe())
}

// Shutdown attempts graceful server shutdown with a 10-second timeout.
func (as *AdminServer) Shutdown() error {
	ctxShutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return as.server.Shutdown(ctxShutdown)
}

// registerRoutes sets up the mux router, middleware, CSRF, gzip, and logging.
func (as *AdminServer) registerRoutes() {
	router := mux.NewRouter()

	// Public and authenticated routes with middleware applied.
	router.HandleFunc("/", mid.Use(as.Base, mid.RequireLogin))
	router.HandleFunc("/login", mid.Use(as.Login, as.limiter.Limit))
	router.HandleFunc("/logout", mid.Use(as.Logout, mid.RequireLogin))
	router.HandleFunc("/reset_password", mid.Use(as.ResetPassword, mid.RequireLogin))

	router.HandleFunc("/campaigns", mid.Use(as.Campaigns, mid.RequireLogin))
	router.HandleFunc("/campaigns/{id:[0-9]+}", mid.Use(as.CampaignID, mid.RequireLogin))
	router.HandleFunc("/templates", mid.Use(as.Templates, mid.RequireLogin))
	router.HandleFunc("/groups", mid.Use(as.Groups, mid.RequireLogin))
	router.HandleFunc("/landing_pages", mid.Use(as.LandingPages, mid.RequireLogin))
	router.HandleFunc("/sending_profiles", mid.Use(as.SendingProfiles, mid.RequireLogin))
	router.HandleFunc("/settings", mid.Use(as.Settings, mid.RequireLogin))
	router.HandleFunc("/users", mid.Use(as.UserManagement, mid.RequirePermission(models.PermissionModifySystem), mid.RequireLogin))
	router.HandleFunc("/webhooks", mid.Use(as.Webhooks, mid.RequirePermission(models.PermissionModifySystem), mid.RequireLogin))
	router.HandleFunc("/impersonate", mid.Use(as.Impersonate, mid.RequirePermission(models.PermissionModifySystem), mid.RequireLogin))

	// API routes
	apiServer := api.NewServer(api.WithWorker(as.worker), api.WithLimiter(as.limiter))
	router.PathPrefix("/api/").Handler(apiServer)

	// Static assets with directory listing disabled
	router.PathPrefix("/").Handler(http.FileServer(unindexed.Dir("./static/")))

	// CSRF protection middleware configuration
	csrfKey := []byte(as.config.CSRFKey)
	if len(csrfKey) == 0 {
		csrfKey = []byte(auth.GenerateSecureKey(auth.APIKeyLength))
		log.Warn("CSRF key not set in config; generated ephemeral key")
	}

	csrfHandler := csrf.Protect(
		csrfKey,
		csrf.FieldName("csrf_token"),
		csrf.Secure(as.config.UseTLS),
		csrf.TrustedOrigins(as.config.TrustedOrigins),
		csrf.Path("/"),
	)

	adminHandler := csrfHandler(router)

	// Middleware chain: CSRF, context, security headers
	adminHandler = mid.Use(adminHandler.ServeHTTP, mid.CSRFExceptions, mid.GetContext, mid.ApplySecurityHeaders)

	// GZIP compression wrapper at best compression level
	gzipWrapper, err := gziphandler.NewGzipLevelHandler(gzip.BestCompression)
	if err != nil {
		log.Fatalf("Failed to create gzip handler: %v", err)
	}
	adminHandler = gzipWrapper(adminHandler)

	// Respect proxy headers like X-Forwarded-For for accurate client IP
	adminHandler = handlers.ProxyHeaders(adminHandler)

	// Access logging middleware (Apache combined log format)
	adminHandler = handlers.CombinedLoggingHandler(log.Writer(), adminHandler)

	as.server.Handler = adminHandler
}

// templateParams holds common data passed to HTML templates.
type templateParams struct {
	Title        string
	Flashes      []interface{}
	User         models.User
	Token        string
	Version      string
	ModifySystem bool
}

// newTemplateParams prepares common template data from request context.
func newTemplateParams(r *http.Request) templateParams {
	user := ctx.Get(r, "user").(models.User)
	session := ctx.Get(r, "session").(*sessions.Session)

	modifySystem, _ := user.HasPermission(models.PermissionModifySystem)

	return templateParams{
		Token:        csrf.Token(r),
		User:         user,
		ModifySystem: modifySystem,
		Version:      config.Version,
		Flashes:      session.Flashes(),
	}
}

// Base renders the dashboard homepage.
func (as *AdminServer) Base(w http.ResponseWriter, r *http.Request) {
	params := newTemplateParams(r)
	params.Title = "Dashboard"
	executeTemplate(w, "dashboard", params)
}

// Campaigns renders the campaigns page.
func (as *AdminServer) Campaigns(w http.ResponseWriter, r *http.Request) {
	params := newTemplateParams(r)
	params.Title = "Campaigns"
	executeTemplate(w, "campaigns", params)
}

// CampaignID renders results for a specific campaign.
func (as *AdminServer) CampaignID(w http.ResponseWriter, r *http.Request) {
	params := newTemplateParams(r)
	params.Title = "Campaign Results"
	executeTemplate(w, "campaign_results", params)
}

// Templates renders the email templates management page.
func (as *AdminServer) Templates(w http.ResponseWriter, r *http.Request) {
	params := newTemplateParams(r)
	params.Title = "Email Templates"
	executeTemplate(w, "templates", params)
}

// Groups renders users and groups management.
func (as *AdminServer) Groups(w http.ResponseWriter, r *http.Request) {
	params := newTemplateParams(r)
	params.Title = "Users & Groups"
	executeTemplate(w, "groups", params)
}

// LandingPages renders the landing pages management.
func (as *AdminServer) LandingPages(w http.ResponseWriter, r *http.Request) {
	params := newTemplateParams(r)
	params.Title = "Landing Pages"
	executeTemplate(w, "landing_pages", params)
}

// SendingProfiles renders the sending profiles management.
func (as *AdminServer) SendingProfiles(w http.ResponseWriter, r *http.Request) {
	params := newTemplateParams(r)
	params.Title = "Sending Profiles"
	executeTemplate(w, "sending_profiles", params)
}

// Settings handles GET/POST requests for changing settings, including password updates.
func (as *AdminServer) Settings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		params := newTemplateParams(r)
		params.Title = "Settings"
		session := ctx.Get(r, "session").(*sessions.Session)
		session.Save(r, w)
		executeTemplate(w, "settings", params)

	case http.MethodPost:
		u := ctx.Get(r, "user").(models.User)
		currentPw := r.FormValue("current_password")
		newPw := r.FormValue("new_password")
		confirmPw := r.FormValue("confirm_new_password")

		if err := auth.ValidatePassword(currentPw, u.Hash); err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		newHash, err := auth.ValidatePasswordChange(u.Hash, newPw, confirmPw)
		if err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		u.Hash = string(newHash)
		if err := models.PutUser(&u); err != nil {
			respondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		respondJSONSuccess(w, "Settings Updated Successfully")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// UserManagement renders the user management page (admin only).
func (as *AdminServer) UserManagement(w http.ResponseWriter, r *http.Request) {
	params := newTemplateParams(r)
	params.Title = "Users"
	executeTemplate(w, "users", params)
}

// Webhooks renders the webhooks management page (admin only).
func (as *AdminServer) Webhooks(w http.ResponseWriter, r *http.Request) {
	params := newTemplateParams(r)
	params.Title = "Webhooks"
	executeTemplate(w, "webhooks", params)
}

// Impersonate allows admins to impersonate other users, updating the session.
func (as *AdminServer) Impersonate(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	user, err := models.GetUserByUsername(username)
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, "User not found")
		return
	}

	session := ctx.Get(r, "session").(*sessions.Session)
	session.Values["user"] = user
	if err := session.Save(r, w); err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to save session")
		return
	}

	respondJSONSuccess(w, "Impersonation successful")
}

// Login handles login POST and GET.
func (as *AdminServer) Login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		params := newTemplateParams(r)
		params.Title = "Login"
		executeTemplate(w, "login", params)

	case http.MethodPost:
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := models.GetUserByUsername(username)
		if err != nil {
			respondJSONError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}

		if user.AccountLocked {
			respondJSONError(w, http.StatusForbidden, "Account is locked")
			return
		}

		if err := auth.ValidatePassword(password, user.Hash); err != nil {
			respondJSONError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}

		session := ctx.Get(r, "session").(*sessions.Session)
		session.Values["user"] = user
		if err := session.Save(r, w); err != nil {
			respondJSONError(w, http.StatusInternalServerError, "Failed to create session")
			return
		}

		next := getNextRedirect(r)
		http.Redirect(w, r, next, http.StatusSeeOther)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Logout clears session and redirects to login.
func (as *AdminServer) Logout(w http.ResponseWriter, r *http.Request) {
	session := ctx.Get(r, "session").(*sessions.Session)
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		log.Warnf("Failed to clear session on logout: %v", err)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ResetPassword processes password reset requests.
func (as *AdminServer) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := ctx.Get(r, "user").(models.User)
	currentPw := r.FormValue("current_password")
	newPw := r.FormValue("new_password")
	confirmPw := r.FormValue("confirm_new_password")

	if err := auth.ValidatePassword(currentPw, user.Hash); err != nil {
		respondJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	newHash, err := auth.ValidatePasswordChange(user.Hash, newPw, confirmPw)
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	user.Hash = string(newHash)
	user.MustChangePassword = false

	if err := models.PutUser(&user); err != nil {
		respondJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSONSuccess(w, "Password successfully updated")
}

// executeTemplate renders a given template with parameters.
func executeTemplate(w http.ResponseWriter, tmpl string, params interface{}) {
	t, err := template.ParseFiles("./templates/" + tmpl + ".html")
	if err != nil {
		log.Errorf("Template parsing error for %s: %v", tmpl, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := t.Execute(w, params); err != nil {
		log.Errorf("Template execution error for %s: %v", tmpl, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// getNextRedirect returns a safe redirect URL from the "next" query parameter.
// Defaults to "/" if parameter is absent or unsafe.
func getNextRedirect(r *http.Request) string {
	next := r.FormValue("next")
	if next == "" {
		return "/"
	}
	// Validate relative path only; no scheme or host allowed.
	if u, err := url.Parse(next); err == nil && u.IsAbs() == false && strings.HasPrefix(u.Path, "/") {
		return u.String()
	}
	return "/"
}

// respondJSONError writes an error message as JSON response.
func respondJSONError(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

// respondJSONSuccess writes a success message as JSON response.
func respondJSONSuccess(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success","message":"` + msg + `"}`))
}
