# Framework - Go Web Framework for Indie Hackers

**Package:** `github.com/dmitrymomot/framework`

## Purpose

Framework is a lightweight Go web framework designed for solo developers building server-side rendered (SSR) applications. It wires together proven Go packages into a cohesive development experience while keeping handlers and business logic under full developer control.

**Not a framework that does everything.** Framework handles application lifecycle, request processing, and infrastructure concerns. You handle routing, handlers, and business logic.

## Design Principles

1. **No Magic Routes** - You define routes explicitly using go-chi
2. **Minimal Boilerplate** - Generic handlers eliminate repetitive code
3. **SSR-First** - Optimized for html/template + HTMX, not JSON APIs
4. **Fail Fast** - Catch errors at startup, not runtime
5. **Solo-Dev Scale** - Simple enough for one person to understand entirely

## Core Stack

| Concern         | Package                 |
| --------------- | ----------------------- |
| Router          | go-chi/chi/v5           |
| Database        | pgx/v5 + sqlc           |
| Migrations      | pressly/goose           |
| Sessions        | alexedwards/scs         |
| Background Jobs | hibiken/asynq           |
| Templates       | html/template           |
| Validation      | go-playground/validator |
| Logging         | log/slog                |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                      HTTP Request                        │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                 Middleware Stack                         │
│  RealIP → RequestID → Logger → Recoverer → CSRF → Auth  │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                   Handle[Req]()                          │
│  Decode → Sanitize → Validate → Execute → Render        │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                    Your Handler                          │
│         func(ctx *Context, req Req) Result              │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                   Result Rendering                       │
│     Page │ Partial │ Redirect │ Toast │ Download │ Err  │
└─────────────────────────────────────────────────────────┘
```

## Framework Structure

```
forge/
├── app.go                  # App struct, New(), Run(), Shutdown()
├── options.go              # WithDatabase(), WithSessions(), etc.
├── context.go              # Context struct, builders, helpers
├── handler.go              # Handle[Req](), generic wrapper
├── results.go              # Result interface, Page, Partial, Redirect, etc.
├── render.go               # App.Render() integration, error rendering
├── errors.go               # AppError definitions
├── sanitize.go             # Struct tag sanitizer
├── validate.go             # Validation wrapper
├── decode.go               # Form/path/query decoder
├── middleware/
│   ├── requestid.go        # X-Request-ID propagation
│   ├── logger.go           # Request logging
│   ├── csrf.go             # CSRF protection
│   ├── recoverer.go        # Panic recovery
│   └── auth.go             # User/tenant loading
├── session/
│   ├── session.go          # scs wrapper, config
│   └── flash.go            # Flash message helpers
├── database/
│   ├── pool.go             # Connection pool setup
│   └── repository.go       # Repository interface with InTx
├── worker/
│   ├── client.go           # Typed enqueue helpers
│   ├── server.go           # Worker server setup
│   └── job.go              # HandleJob[T] generic wrapper
├── health/
│   └── routes.go           # /health/live, /health/ready
├── logging/
│   ├── logger.go           # Structured logger setup
│   └── context.go          # Context-aware log handler
├── i18n/
│   ├── translator.go       # Translator, Load(), T()
│   ├── middleware.go       # Locale detection
│   └── locales/            # Embedded JSON files
├── render/
│   ├── renderer.go         # Template loading, Render()
│   ├── data.go             # TemplateData, TemplateContext
│   └── funcs.go            # Built-in template functions
├── pagination/
│   └── pagination.go       # Pagination helpers
├── upload/
│   └── upload.go           # File upload/download helpers
└── cmd/
    └── forge/
        ├── main.go         # CLI entrypoint
        ├── new.go          # Project scaffolding
        └── scaffold/       # Embedded templates
```

## Core Components

### App Struct

Central container for all application dependencies. Initialized once at startup.

```go
type App struct {
    Config   *Config
    DB       *pgxpool.Pool
    Repo     Repository
    Router   chi.Router
    Sessions *scs.SessionManager
    Queue    *asynq.Client
    Workers  *asynq.ServeMux
    Logger   *slog.Logger
    Renderer *render.Renderer
    I18n     *Translator

    onStart []func(context.Context) error
    onStop  []func(context.Context) error
}
```

### Context

Framework provides a base context. Apps define custom contexts for different route groups.

**Framework: Base Context**

```go
// github.com/dmitrymomot/framework/context.go
type BaseContext struct {
    context.Context
    Locale string
    IsHTMX bool
    values map[string]any
}

func (c *BaseContext) Set(key string, val any)
func Get[T any](c *BaseContext, key string) T
```

**Scaffolded App: Custom Contexts**

```go
// internal/app/context.go

// Base for all routes
type Context struct {
    *framework.BaseContext
    App *App
}

func (c *Context) Repo() *db.Queries { return c.App.Repo }
func (c *Context) T(key string, args ...any) string {
    return c.App.I18n.T(c.Locale, key, args...)
}
func (c *Context) Enqueue(taskType string, payload any) error {
    return c.App.enqueue(taskType, payload)
}

// Public routes - no auth required
type PublicContext struct {
    *Context
}

// Authenticated routes
type AuthContext struct {
    *Context
    User   *User
    Tenant *Tenant
    Role   Role
}

// Admin routes
type AdminContext struct {
    *AuthContext
    Permissions []Permission
}
```

### Context Factories

Define how contexts are built for different route groups.

```go
// internal/app/handler.go

func Public(app *App) framework.ContextFactory[PublicContext] {
    return func(r *http.Request, base *framework.BaseContext) (*PublicContext, error) {
        return &PublicContext{
            Context: &Context{BaseContext: base, App: app},
        }, nil
    }
}

func Auth(app *App) framework.ContextFactory[AuthContext] {
    return func(r *http.Request, base *framework.BaseContext) (*AuthContext, error) {
        user := UserFrom(r.Context())
        if user == nil {
            return nil, framework.ErrUnauthorized
        }
        return &AuthContext{
            Context: &Context{BaseContext: base, App: app},
            User:    user,
            Tenant:  TenantFrom(r.Context()),
            Role:    RoleFrom(r.Context()),
        }, nil
    }
}

func Admin(app *App) framework.ContextFactory[AdminContext] {
    return func(r *http.Request, base *framework.BaseContext) (*AdminContext, error) {
        ctx, err := Auth(app)(r, base)
        if err != nil {
            return nil, err
        }
        if ctx.Role != RoleAdmin {
            return nil, framework.ErrForbidden
        }
        perms, _ := app.Repo.GetPermissions(r.Context(), ctx.User.ID)
        return &AdminContext{AuthContext: ctx, Permissions: perms}, nil
    }
}
```

### Handler Signature

Clean handlers focused on business logic, parameterized by context type.

**Framework**

```go
// github.com/dmitrymomot/framework/handler.go
type Handler[Ctx, Req any] func(ctx *Ctx, req Req) Result

type ContextFactory[Ctx any] func(r *http.Request, base *BaseContext) (*Ctx, error)

func Handle[Ctx, Req any](
    factory ContextFactory[Ctx],
    h Handler[Ctx, Req],
    render ErrorRenderer,
) http.HandlerFunc
```

**Scaffolded App**

```go
// Handlers use specific context types
func ShowPricing(ctx *PublicContext, req struct{}) framework.Result { ... }
func Dashboard(ctx *AuthContext, req DashboardReq) framework.Result { ... }
func AdminPanel(ctx *AdminContext, req struct{}) framework.Result { ... }
```

### Result Types

```go
// Full page render
func Page(name string, data any) Result

// HTMX partial
func Partial(name string, data any) Result

// Form with validation errors
func FormError(name string, data any, errors ValidationErrors) Result

// Success/error toast (HTMX)
func Toast(message string) Result
func ToastError(message string) Result

// Redirect (HTMX-aware)
func Redirect(url string) Result

// JSON response
func JSON(data any) Result

// File download
func Download(filename, contentType string, data io.Reader) Result

// Error (renders toast or error page based on IsHTMX)
func Err(err error) Result

// Auto-select page vs partial based on IsHTMX
func Render(page, partial string, data any) Result
```

## Template Rendering

### Renderer

Convention-based template renderer with layout support, wrapping stdlib `html/template`.

```go
// github.com/dmitrymomot/framework/render/renderer.go
type Renderer struct {
    templates     map[string]*template.Template
    layouts       map[string]*template.Template
    funcs         template.FuncMap
    defaultLayout string
    viewsFS       fs.FS
    isDev         bool
}

type Config struct {
    ViewsFS       fs.FS
    DefaultLayout string
    FuncMap       template.FuncMap
    IsDev         bool
}

func New(cfg Config) (*Renderer, error)
func (r *Renderer) Render(w io.Writer, name string, data any) error
```

### Template Directory Structure

```
templates/
├── layouts/
│   ├── base.html       # Main layout
│   ├── admin.html      # Admin layout
│   └── auth.html       # Minimal auth layout
├── partials/
│   ├── nav.html
│   ├── footer.html
│   └── flash.html
└── pages/
    ├── home.html
    ├── users/
    │   ├── index.html
    │   ├── show.html
    │   └── _row.html   # HTMX partial (no layout)
    └── admin/
        └── dashboard.html
```

### Conventions

| Convention                | Behavior                              |
| ------------------------- | ------------------------------------- |
| `pages/**/*.html`         | Auto-wrapped in default layout        |
| `pages/**/_*.html`        | Partial, no layout (for HTMX)         |
| `{{/* layout: admin */}}` | Override layout per-page              |
| `{{/* layout: none */}}`  | Explicitly disable layout             |
| `partials/**/*.html`      | Available via `{{template "name" .}}` |

### Template Context

```go
// github.com/dmitrymomot/framework/render/data.go
type TemplateData struct {
    Data    any
    Ctx     *TemplateContext
    Content template.HTML // Rendered page content for layouts
}

type TemplateContext struct {
    Locale    string
    CSRFToken string
    FlashType string
    FlashMsg  string
    User      any
    Tenant    any
    Path      string
    IsHTMX    bool
}
```

### Built-in Template Functions

```go
func ContextFuncs(getCtx func() *TemplateContext) template.FuncMap {
    return template.FuncMap{
        "ctx":         func() *TemplateContext { return getCtx() },
        "t":           func(key string, args ...any) string { /* i18n */ },
        "T":           func(key string, args ...any) template.HTML { /* i18n, trusted */ },
        "isActive":    func(path string) bool { return getCtx().Path == path },
        "csrfField":   func() template.HTML { /* hidden input */ },
        "currentUser": func() any { return getCtx().User },
        "flash":       func() (string, string) { /* type, message */ },
    }
}
```

### Layout Example

```html
<!-- layouts/base.html -->
<!DOCTYPE html>
<html lang="{{.Ctx.Locale}}">
    <head>
        <title>{{block "title" .}}App{{end}}</title>
    </head>
    <body>
        {{template "nav" .}} {{template "flash" .}}
        <main>{{.Content}}</main>
        {{template "footer" .}}
    </body>
</html>
```

### Partial Examples

```html
<!-- partials/nav.html -->
<nav>
    <a href="/" class="{{if isActive "/"}}active{{end}}">Home</a>
    {{if currentUser}}
        <a href="/dashboard">Dashboard</a>
        <span>{{currentUser.Name}}</span>
    {{else}}
        <a href="/login">Login</a>
    {{end}}
</nav>
```

```html
<!-- partials/flash.html -->
{{$type, $msg := flash}} {{if $msg}}
<div class="alert alert-{{$type}}">{{$msg}}</div>
{{end}}
```

### Page Examples

```html
<!-- pages/users/show.html -->
{{define "title"}}{{.Data.User.Name}} | App{{end}}

<h1>{{.Data.User.Name}}</h1>
<p>{{.Data.User.Email}}</p>

<form method="post" action="/users/{{.Data.User.ID}}">
    {{csrfField}}
    <button type="submit">Update</button>
</form>
```

```html
<!-- pages/admin/dashboard.html -->
{{/* layout: admin */}}

<h1>Admin Dashboard</h1>
```

```html
<!-- pages/users/_row.html (HTMX partial, no layout) -->
{{/* layout: none */}}

<tr id="user-{{.Data.ID}}">
    <td>{{.Data.Name}}</td>
    <td>{{.Data.Email}}</td>
</tr>
```

### Framework Integration

```go
// framework/render.go
func (app *App) Render(w http.ResponseWriter, r *http.Request, name string, data any) error {
    ctx := ContextFrom(r.Context())

    tplData := &render.TemplateData{
        Data: data,
        Ctx: &render.TemplateContext{
            Locale:    ctx.Locale,
            CSRFToken: app.CSRFToken(r.Context()),
            FlashType: app.Sessions.PopString(r.Context(), "flash_type"),
            FlashMsg:  app.Sessions.PopString(r.Context(), "flash_msg"),
            Path:      r.URL.Path,
            IsHTMX:    ctx.IsHTMX,
        },
    }

    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    return app.Renderer.Render(w, name, tplData)
}
```

## Request Processing

### Struct Tags

```go
type CreateUserReq struct {
    Email string `form:"email" path:"-" validate:"required,email" sanitize:"trim,lowercase"`
    Name  string `form:"name" validate:"required,min=2" sanitize:"trim"`
    OrgID int64  `path:"org_id" form:"-"`
}
```

| Tag        | Purpose                                    |
| ---------- | ------------------------------------------ |
| `form`     | Form field name                            |
| `path`     | URL path parameter                         |
| `query`    | Query string parameter                     |
| `validate` | Validation rules (go-playground/validator) |
| `sanitize` | Sanitization: trim, lowercase, html        |

### Handler Wrapper Flow

```go
// github.com/dmitrymomot/framework/handler.go
func Handle[Ctx, Req any](
    factory ContextFactory[Ctx],
    h Handler[Ctx, Req],
    render ErrorRenderer,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req Req

        // 1. Decode form/path/query into struct
        if err := Decode(r, &req); err != nil {
            render.RenderError(w, r, err, http.StatusBadRequest)
            return
        }

        // 2. Sanitize string fields
        Sanitize(&req)

        // 3. Validate
        if errs := Validate(req); errs != nil {
            // Handle validation errors
            return
        }

        // 4. Build base context
        base := &BaseContext{
            Context: r.Context(),
            Locale:  LocaleFrom(r.Context()),
            IsHTMX:  r.Header.Get("HX-Request") == "true",
            values:  make(map[string]any),
        }

        // 5. Build custom context via factory
        ctx, err := factory(r, base)
        if err != nil {
            render.RenderError(w, r, err, errorStatus(err))
            return
        }

        // 6. Execute handler
        result := h(ctx, req)

        // 7. Render result
        result.Render(w, r)
    }
}
```

## Usage Examples

### Basic Handler

```go
type ShowUserReq struct {
    ID int64 `path:"id"`
}

func ShowUser(ctx *AuthContext, req ShowUserReq) framework.Result {
    user, err := ctx.Repo().GetUser(ctx, req.ID)
    if err != nil {
        return framework.Err(err)
    }
    return framework.Page("users/show", user)
}

// Route
r.Get("/users/{id}", framework.Handle(Auth(app), ShowUser, app))
```

### Form Handler

```go
type CreateUserReq struct {
    Email string `form:"email" validate:"required,email" sanitize:"trim,lowercase"`
    Name  string `form:"name" validate:"required" sanitize:"trim"`
}

func CreateUser(ctx *AuthContext, req CreateUserReq) framework.Result {
    user, err := ctx.Repo().CreateUser(ctx, db.CreateUserParams{
        Email:    req.Email,
        Name:     req.Name,
        TenantID: ctx.Tenant.ID,
    })
    if err != nil {
        if errors.Is(err, ErrEmailTaken) {
            return framework.FormError("users/form", req, V{"email": "Already taken"})
        }
        return framework.Err(err)
    }

    ctx.Flash("success", "User created")
    return framework.Redirect("/users/" + strconv.FormatInt(user.ID, 10))
}

// Route
r.Post("/users", framework.Handle(Auth(app), CreateUser, app))
```

### HTMX Handler

```go
func CreateUser(ctx *AuthContext, req CreateUserReq) framework.Result {
    user, err := ctx.Repo().CreateUser(ctx, /* ... */)
    if err != nil {
        return framework.Err(err) // Renders toast on HTMX, error page otherwise
    }

    if ctx.IsHTMX {
        return framework.Partial("users/_row", user)
    }
    return framework.Redirect("/users/" + user.ID)
}
```

### Public vs Authenticated Routes

```go
// Public - no auth required
func ShowPricing(ctx *PublicContext, req struct{}) framework.Result {
    plans, _ := ctx.Repo().GetPlans(ctx)
    return framework.Page("pricing", plans)
}

// Authenticated - user required
func Dashboard(ctx *AuthContext, req struct{}) framework.Result {
    stats, _ := ctx.Repo().GetStats(ctx, ctx.Tenant.ID)
    return framework.Page("dashboard", stats)
}

// Admin - role check in factory
func AdminPanel(ctx *AdminContext, req struct{}) framework.Result {
    // ctx.Permissions available
    return framework.Page("admin/panel", ctx.Permissions)
}

// Routes
r.Get("/pricing", framework.Handle(Public(app), ShowPricing, app))
r.Get("/dashboard", framework.Handle(Auth(app), Dashboard, app))
r.Get("/admin", framework.Handle(Admin(app), AdminPanel, app))
```

### Background Job

```go
// In handler
func CreateUser(ctx *AuthContext, req CreateUserReq) framework.Result {
    user, err := ctx.Repo().CreateUser(ctx, /* ... */)
    if err != nil {
        return framework.Err(err)
    }

    // Enqueue welcome email
    ctx.Enqueue("email:welcome", WelcomePayload{
        UserID: user.ID,
        Email:  user.Email,
    })

    return framework.Redirect("/users/" + user.ID)
}

// Worker registration
func RegisterWorkers(app *App) []framework.TaskHandler {
    return []framework.TaskHandler{
        {"email:welcome", framework.HandleJob(app, SendWelcomeEmail)},
        {"report:generate", framework.HandleJob(app, GenerateReport)},
    }
}
```

### Job Handler Wrapper

Generic wrapper eliminates boilerplate in job handlers.

```go
type Job[T any] func(ctx context.Context, app *App, payload T) error

func HandleJob[T any](app *App, handler Job[T]) asynq.HandlerFunc {
    return func(ctx context.Context, task *asynq.Task) error {
        var payload T
        if err := json.Unmarshal(task.Payload(), &payload); err != nil {
            app.Logger.Error("job payload decode failed",
                "type", task.Type(),
                "error", err,
            )
            return fmt.Errorf("decode payload: %w", err)
        }

        app.Logger.Info("job started", "type", task.Type())

        if err := handler(ctx, app, payload); err != nil {
            // Skip retries for permanent errors
            if errors.Is(err, ErrPermanent) {
                app.Logger.Error("job failed permanently",
                    "type", task.Type(),
                    "error", err,
                )
                return nil
            }
            app.Logger.Error("job failed",
                "type", task.Type(),
                "error", err,
            )
            return err
        }

        app.Logger.Info("job completed", "type", task.Type())
        return nil
    }
}

// Worker implementation - clean, no boilerplate
func SendWelcomeEmail(ctx context.Context, app *App, p WelcomePayload) error {
    user, err := app.Repo.GetUser(ctx, p.UserID)
    if err != nil {
        return err
    }
    return app.Mailer.Send(p.Email, "welcome", user)
}
```

### Transaction

```go
func TransferCredits(ctx *AuthContext, req TransferReq) framework.Result {
    err := ctx.Repo().InTx(ctx, func(r Repository) error {
        if err := r.DeductCredits(ctx, req.FromID, req.Amount); err != nil {
            return err
        }
        return r.AddCredits(ctx, req.ToID, req.Amount)
    })
    if err != nil {
        return framework.Err(err)
    }
    return framework.Redirect("/credits")
}
```

## Database

### Repository Interface

```go
type Repository interface {
    Querier // sqlc-generated interface
    InTx(ctx context.Context, fn func(Repository) error) error
}
```

### Pool Configuration

```go
type DBConfig struct {
    URL             string        `env:"DATABASE_URL,required"`
    MaxConns        int32         `env:"DB_MAX_CONNS" envDefault:"10"`
    MinConns        int32         `env:"DB_MIN_CONNS" envDefault:"2"`
    MaxConnLifetime time.Duration `env:"DB_MAX_CONN_LIFETIME" envDefault:"1h"`
    MaxConnIdleTime time.Duration `env:"DB_MAX_CONN_IDLE" envDefault:"30m"`
}
```

## Middleware

All middleware use app's error renderer—no raw `http.Error()` calls.

### Default Stack

```go
app.Router.Use(
    middleware.RealIP,
    RequestIDMiddleware(),
    LoggerMiddleware(app),
    RecovererMiddleware(app),
    app.Sessions.LoadAndSave,
)
```

### CSRF (POST/PUT/DELETE routes)

```go
r.Route("/", func(r chi.Router) {
    r.Use(CSRFMiddleware(app))
    r.Post("/users", Handle(app, CreateUser))
})
```

### Auth (protected routes)

```go
r.Route("/app", func(r chi.Router) {
    r.Use(AuthMiddleware(app)) // Loads user, tenant, role into context
    r.Get("/dashboard", Handle(app, Dashboard))
})
```

## Sessions & Flash Messages

### Session Setup

```go
WithSessions(scs.NewPostgresStore(pool)) // or Redis, memory, etc.
```

### Flash Messages

```go
// Set in handler
ctx.Flash("success", "User created successfully")
ctx.Flash("error", "Something went wrong")

// Read in template (auto-cleared after read)
{{ if .Flash.Message }}
    <div class="alert alert-{{ .Flash.Type }}">{{ .Flash.Message }}</div>
{{ end }}
```

### CSRF Token in Templates

```go
// Template function
{{ csrfField .Ctx }}

// Renders
<input type="hidden" name="csrf_token" value="abc123">
```

## Error Handling

### Application Errors

```go
var (
    ErrNotFound     = AppError{Code: "not_found", Status: 404}
    ErrUnauthorized = AppError{Code: "unauthorized", Status: 401}
    ErrForbidden    = AppError{Code: "forbidden", Status: 403}
    ErrConflict     = AppError{Code: "conflict", Status: 409}
)

// Usage
if user == nil {
    return Err(ErrNotFound.WithMessage("User not found"))
}
```

### Error Rendering

Errors render differently based on request type:

| Request Type | Error Display                                 |
| ------------ | --------------------------------------------- |
| Regular      | Error page (errors/404.html, errors/500.html) |
| HTMX         | Toast notification                            |

## Logging

### Context-Aware Logger

Automatically includes request_id, user_id, tenant_id in all log entries.

```go
// In handler
ctx.app.Logger.Info("user created", "email", user.Email)

// Output
{"time":"...","level":"INFO","msg":"user created","request_id":"abc123","user_id":42,"email":"..."}
```

## Health Checks

Built-in endpoints:

| Endpoint            | Purpose                      |
| ------------------- | ---------------------------- |
| `GET /health/live`  | App is running               |
| `GET /health/ready` | App + all dependencies ready |

```json
// GET /health/ready
{
    "postgres": "ok",
    "redis": "ok"
}
```

## Internationalization (i18n)

### Translator

```go
type Translator struct {
    messages map[string]map[string]string // locale -> key -> message
    fallback string
}

func (t *Translator) T(locale, key string, args ...any) string
```

### Message Files

```json
// locales/en.json
{
    "welcome": "Welcome, %s!",
    "users.created": "User created successfully",
    "errors.not_found": "Resource not found",
    "validation.required": "This field is required"
}
```

```json
// locales/uk.json
{
    "welcome": "Вітаємо, %s!",
    "users.created": "Користувача створено",
    "errors.not_found": "Ресурс не знайдено",
    "validation.required": "Це поле обов'язкове"
}
```

### Context Integration

```go
func (c *Context) T(key string, args ...any) string {
    return c.app.I18n.T(c.Locale, key, args...)
}
```

### Template Functions

```go
// t - returns string
// T - returns template.HTML (for trusted content with markup)

func (app *App) templateFuncs(ctx context.Context) template.FuncMap {
    locale := LocaleFrom(ctx)
    return template.FuncMap{
        "t": func(key string, args ...any) string {
            return app.I18n.T(locale, key, args...)
        },
        "T": func(key string, args ...any) template.HTML {
            return template.HTML(app.I18n.T(locale, key, args...))
        },
    }
}
```

### Template Usage

```html
<h1>{{ t "welcome" .User.Name }}</h1>

<button type="submit">{{ t "buttons.save" }}</button>

{{ if .Errors.Email }}
<span class="error">{{ t "validation.email" }}</span>
{{ end }}
```

### Locale Detection Middleware

Priority: query param → cookie → Accept-Language header → fallback

```go
func LocaleMiddleware(app *App, supported []string, fallback string) func(http.Handler) http.Handler
```

## CLI Scaffolding

### New Project

```bash
framework new myapp \
    --module github.com/user/myapp \
    --db postgres \
    --auth \
    --tenancy
```

### Generated Structure

```
myapp/
├── cmd/app/main.go
├── internal/
│   ├── app/
│   │   ├── app.go              # App struct embedding framework.App
│   │   ├── context.go          # Context, PublicContext, AuthContext
│   │   └── handler.go          # Context factories: Public(), Auth()
│   ├── config/config.go
│   ├── handlers/
│   │   ├── auth.go
│   │   ├── public.go
│   │   └── dashboard.go
│   ├── middleware/
│   ├── models/                 # User, Tenant, Role
│   ├── workers/
│   └── routes.go
├── migrations/
│   ├── 001_base.sql
│   └── 002_auth.sql
├── queries/
│   ├── base.sql
│   └── auth.sql
├── templates/
│   ├── layouts/
│   │   ├── base.html
│   │   ├── admin.html
│   │   └── auth.html
│   ├── partials/
│   │   ├── nav.html
│   │   ├── footer.html
│   │   └── flash.html
│   ├── pages/
│   │   ├── home.html
│   │   ├── auth/
│   │   │   ├── login.html
│   │   │   └── register.html
│   │   └── errors/
│   │       ├── 404.html
│   │       └── 500.html
│   └── emails/             # Email templates (if using mailer)
├── locales/
│   └── en.json
├── .air.toml
├── .env.example
└── go.mod
```

## Testing

### Test Helpers

```go
func TestApp(t *testing.T) *App {
    t.Helper()
    pool := setupTestDB(t)
    t.Cleanup(func() { cleanupTestDB(pool) })

    return New(
        WithDatabase(pool),
        WithTestSessions(),
    )
}

func TestContext(app *App, user *User, tenant *Tenant) *AuthContext {
    return &AuthContext{
        Context: &Context{
            BaseContext: &framework.BaseContext{
                Context: context.Background(),
                Locale:  "en",
            },
            App: app,
        },
        User:   user,
        Tenant: tenant,
        Role:   RoleUser,
    }
}

func TestPublicContext(app *App) *PublicContext {
    return &PublicContext{
        Context: &Context{
            BaseContext: &framework.BaseContext{
                Context: context.Background(),
                Locale:  "en",
            },
            App: app,
        },
    }
}
```

### Handler Test

```go
func TestCreateUser(t *testing.T) {
    app := TestApp(t)
    ctx := TestContext(app, adminUser, testTenant)

    result := CreateUser(ctx, CreateUserReq{
        Email: "test@example.com",
        Name:  "Test User",
    })

    redirect, ok := result.(framework.RedirectResult)
    assert.True(t, ok)
    assert.Contains(t, redirect.URL, "/users/")
}
```

### Integration Test

```go
func TestCreateUserIntegration(t *testing.T) {
    app := TestApp(t)

    rec := TestRequest(app, "POST", "/users", map[string]string{
        "email": "test@example.com",
        "name":  "Test User",
    })

    assert.Equal(t, http.StatusSeeOther, rec.Code)
}
```

## Performance Characteristics

| Component                    | Overhead  |
| ---------------------------- | --------- |
| App pointer dereference      | <1ns      |
| Context allocation           | ~50ns     |
| Sanitize (reflection)        | 1-5μs     |
| Validate (reflection)        | 1-5μs     |
| **Total framework overhead** | **<10μs** |

Real bottlenecks: Database (1-50ms), Template rendering (0.1-1ms)

## Configuration

All configuration via environment variables:

```bash
# Database
DATABASE_URL=postgres://localhost/myapp
DB_MAX_CONNS=10
DB_MIN_CONNS=2

# Redis
REDIS_URL=redis://localhost:6379

# Server
PORT=8080
HOST=0.0.0.0

# Sessions
SESSION_SECRET=your-secret-key

# App
LOG_LEVEL=info
```

## Dependencies

```go
require (
    github.com/go-chi/chi/v5
    github.com/jackc/pgx/v5
    github.com/alexedwards/scs/v2
    github.com/hibiken/asynq
    github.com/go-playground/validator/v10
    github.com/microcosm-cc/bluemonday
    github.com/caarlos0/env/v10
)
```

## Why Not Use X?

| Alternative    | Why Not                                        |
| -------------- | ---------------------------------------------- |
| Gin/Echo/Fiber | More abstraction than needed, different router |
| Buffalo        | Abandoned, too opinionated                     |
| Encore         | Cloud-locked, not self-hostable                |
| Loco (Rust)    | Different language, longer iteration cycles    |

Framework exists because the Go ecosystem has great packages but no lightweight glue for SSR apps that respects developer control.
