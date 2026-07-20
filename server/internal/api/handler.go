// Package api provides HTTP handlers for the zk-ai server.
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/kennguy3n/zk-ai/internal/inference"
	"github.com/kennguy3n/zk-ai/internal/privacy"
)

// Handler provides HTTP handlers for AI inference.
type Handler struct {
	engine *inference.Engine
	guard  *privacy.Guard
	logger *slog.Logger
}

// NewHandler creates a new API handler.
func NewHandler(engine *inference.Engine, guard *privacy.Guard, logger *slog.Logger) *Handler {
	return &Handler{
		engine: engine,
		guard:  guard,
		logger: logger,
	}
}

// InferRequest is the JSON body for POST /api/ai/infer.
type InferRequest struct {
	Task             string                 `json:"task"`
	Language         string                 `json:"language"`
	Input            string                 `json:"input"`
	FolderEncryption string                 `json:"folder_encryption_mode"`
	TargetLanguage   string                 `json:"target_language,omitempty"`
	Options          map[string]interface{} `json:"options,omitempty"`
	inputBytes       []byte                 // raw body bytes for wiping
}

// InferResponse is the JSON response for POST /api/ai/infer.
type InferResponse struct {
	Output     string `json:"output"`
	Task       string `json:"task"`
	Model      string `json:"model"`
	Adapter    string `json:"adapter,omitempty"`
	DurationMs uint64 `json:"duration_ms"`
}

// Infer handles POST /api/ai/infer.
func (h *Handler) Infer(w http.ResponseWriter, r *http.Request) {
	// Read body into a byte slice so we can wipe it after inference
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var req InferRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.inputBytes = bodyBytes

	// Extract tenant ID from JWT context (simplified — real impl
	// would extract from auth middleware)
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "anonymous"
	}

	// Privacy guard: check folder mode + rate limit
	if err := h.guard.Check(tenantID, req.FolderEncryption); err != nil {
		status := http.StatusForbidden
		if err == privacy.ErrRateLimited {
			status = http.StatusTooManyRequests
		}
		h.logger.Warn("privacy guard rejected request",
			"tenant", tenantID,
			"task", req.Task,
			"error", err.Error(),
		)
		writeJSONError(w, err.Error(), status)
		return
	}

	// Dispatch to the appropriate inference method
	var result *inference.TaskResult
	var inferErr error

	switch req.Task {
	case "summarize":
		result, inferErr = h.engine.Summarize(req.Input, req.Language)
	case "translate":
		result, inferErr = h.engine.Translate(req.Input, req.Language, req.TargetLanguage)
	case "key_points":
		result, inferErr = h.engine.KeyPoints(req.Input, req.Language)
	default:
		writeJSONError(w, "unsupported task: "+req.Task, http.StatusBadRequest)
		return
	}

	if inferErr != nil {
		h.logger.Error("inference failed",
			"task", req.Task,
			"error", inferErr.Error(),
		)
		writeJSONError(w, "inference failed", http.StatusInternalServerError)
		return
	}

	// Log only metadata, never content
	h.logger.Info("inference completed",
		"task", req.Task,
		"language", req.Language,
		"model", result.Model,
		"duration_ms", result.DurationMs,
	)

	// Build response
	resp := InferResponse{
		Output:     result.Output,
		Task:       result.Task,
		Model:      result.Model,
		Adapter:    result.Adapter,
		DurationMs: result.DurationMs,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	// Wipe the raw request body from memory
	privacy.Wipe(bodyBytes)
	req.Input = ""
}

// DeviceProfile handles GET /api/ai/profile.
func (h *Handler) DeviceProfile(w http.ResponseWriter, r *http.Request) {
	profile, err := h.engine.DeviceProfile()
	if err != nil {
		writeJSONError(w, "failed to get device profile", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

// writeJSONError writes a JSON error response with proper escaping.
func writeJSONError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
