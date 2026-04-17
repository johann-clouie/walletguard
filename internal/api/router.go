package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example/walletguard/internal/audit"
	"github.com/example/walletguard/internal/storage"
)

// Server exposes read-only JSON APIs for findings and incidents.
type Server struct {
	Pool *pgxpool.Pool
}

// NewRouter mounts HTTP handlers.
func NewRouter(pool *pgxpool.Pool) http.Handler {
	s := &Server{Pool: pool}
	st := &storage.PostgresStore{Pool: pool}
	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	r.Get("/api/v1/findings", s.withAudit("list_findings", func(w http.ResponseWriter, r *http.Request) {
		rows, err := st.ListFindings(r.Context(), 100)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows)
	}))
	r.Get("/api/v1/findings/{id}", s.withAudit("get_finding", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		row, err := st.GetFinding(r.Context(), id)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, row)
	}))
	r.Get("/api/v1/incidents", s.withAudit("list_incidents", func(w http.ResponseWriter, r *http.Request) {
		rows, err := st.ListIncidents(r.Context(), 100)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows)
	}))
	r.Post("/api/v1/scan/start", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"use_walletguard_scanner_cli","hint":"run cmd/scanner with SCAN_ROOTS"}`))
	})
	return r
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func (s *Server) withAudit(action string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = audit.Log(r.Context(), s.Pool, "api", action, "http", r.URL.Path, map[string]any{"method": r.Method})
		h(w, r)
	}
}
