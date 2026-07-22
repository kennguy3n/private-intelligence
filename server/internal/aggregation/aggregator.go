// Package aggregation provides a mock server-side aggregation endpoint
// with cohort suppression and differential privacy noise simulation.
//
// This is a MOCK implementation for testing and demonstration purposes.
// It does not perform real secure aggregation or cryptographic DP.
// In production, this would use secure multi-party computation (MPC)
// or federated learning with proper DP mechanisms.
package aggregation

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"sync"
	"time"
)

// MinCohortSize is the minimum number of devices required before a cohort
// is included in the aggregate. Cohorts below this size are suppressed
// to prevent re-identification.
const MinCohortSize = 5

// DefaultEpsilon is the default DP epsilon parameter.
const DefaultEpsilon = 1.0

// CounterTableSubmission represents a device's counter table contribution.
//
// All table fields use flat map[string]int with pipe-delimited keys matching
// the Rust CounterTables JSON format:
//   - risk_calibration:  "channel|language|risk_bucket|feedback_kind"
//   - family_accuracy:   "predicted_family|feedback_kind"
//   - indicator_usefulness: "indicator_id|indicator_strength|feedback_kind"
//   - family_confusion:  "fb:predicted_family|feedback_kind" or "cf:predicted_family|corrected_family"
//   - model_version_stats: "model_version|channel|feedback_kind"
type CounterTableSubmission struct {
	DeviceID          string         `json:"device_id"` // Hashed/pseudonymous, never raw
	RiskCalibration   map[string]int `json:"risk_calibration"`
	FamilyAccuracy    map[string]int `json:"family_accuracy"`
	IndicatorUseful   map[string]int `json:"indicator_usefulness"`
	FamilyConfusion   map[string]int `json:"family_confusion"`
	ModelVersionStats map[string]int `json:"model_version_stats"`
	TotalEvents       int            `json:"total_events"`
	WeekBucket        string         `json:"week_bucket"`
}

// AggregationRequest is the JSON body for POST /api/aggregate.
type AggregationRequest struct {
	Submissions []CounterTableSubmission `json:"submissions"`
	Epsilon     float64                  `json:"epsilon"`
	Delta       float64                  `json:"delta"`
}

// AggregationResponse is the result of the mock aggregation.
type AggregationResponse struct {
	SchemaVersion          string                    `json:"schema_version"`
	WeekBucket             string                    `json:"week_bucket"`
	TotalDevices           int                       `json:"total_devices"`
	SuppressedCohorts      int                       `json:"suppressed_cohorts"`
	RiskCalibration        map[string]AggregatedCell `json:"risk_calibration"`
	FamilyAccuracy         map[string]AggregatedCell `json:"family_accuracy"`
	IndicatorUsefulness    map[string]AggregatedCell `json:"indicator_usefulness"`
	FamilyConfusion        map[string]AggregatedCell `json:"family_confusion"`
	ModelVersionComparison map[string]AggregatedCell `json:"model_version_comparison"`
	DPNoiseApplied         bool                      `json:"dp_noise_applied"`
	EpsilonUsed            float64                   `json:"epsilon_used"`
}

// AggregatedCell represents a single aggregated counter cell with DP noise.
type AggregatedCell struct {
	RawCount    int     `json:"raw_count"`
	NoisyCount  float64 `json:"noisy_count"`
	DeviceCount int     `json:"device_count"`
	Suppressed  bool    `json:"suppressed"`
}

// Aggregator is the mock aggregation server.
type Aggregator struct {
	mu        sync.Mutex
	rng       *rand.Rand
	epsilon   float64
	minCohort int
}

// NewAggregator creates a new mock aggregator with default settings.
func NewAggregator() *Aggregator {
	return &Aggregator{
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
		epsilon:   DefaultEpsilon,
		minCohort: MinCohortSize,
	}
}

// Aggregate processes counter table submissions and returns aggregated
// results with cohort suppression and DP noise.
func (a *Aggregator) Aggregate(req AggregationRequest) AggregationResponse {
	a.mu.Lock()
	defer a.mu.Unlock()

	epsilon := req.Epsilon
	if epsilon <= 0 {
		epsilon = a.epsilon
	}
	// delta is accepted for API compatibility but unused with Laplace mechanism.
	// In production, a Gaussian mechanism would use delta for (ε, δ)-DP.
	_ = req.Delta

	// Determine the week bucket (use the most common one)
	weekBucket := ""
	if len(req.Submissions) > 0 {
		weekBucket = req.Submissions[0].WeekBucket
	}

	// Aggregate each table type
	riskCal := aggregateTable(extractRiskCalibration(req.Submissions), a.minCohort, epsilon, a.rng)
	famAcc := aggregateTable(extractFamilyAccuracy(req.Submissions), a.minCohort, epsilon, a.rng)
	indUse := aggregateTable(extractIndicatorUsefulness(req.Submissions), a.minCohort, epsilon, a.rng)
	famConf := aggregateTable(extractFamilyConfusion(req.Submissions), a.minCohort, epsilon, a.rng)
	mvStats := aggregateTable(extractModelVersionStats(req.Submissions), a.minCohort, epsilon, a.rng)

	suppressedCount := countSuppressed(riskCal) + countSuppressed(famAcc) +
		countSuppressed(indUse) + countSuppressed(famConf) + countSuppressed(mvStats)

	return AggregationResponse{
		SchemaVersion:          "1.0.0",
		WeekBucket:             weekBucket,
		TotalDevices:           len(req.Submissions),
		SuppressedCohorts:      suppressedCount,
		RiskCalibration:        riskCal,
		FamilyAccuracy:         famAcc,
		IndicatorUsefulness:    indUse,
		FamilyConfusion:        famConf,
		ModelVersionComparison: mvStats,
		DPNoiseApplied:         true,
		EpsilonUsed:            epsilon,
	}
}

// cellKey creates a unique key for a counter cell.
func cellKey(parts ...string) string {
	key := ""
	for i, p := range parts {
		if i > 0 {
			key += "|"
		}
		key += p
	}
	return key
}

// extractCounters collects all counts for each flat key across submissions.
// The key is used as-is (already contains all dimensions from the Rust side).
func extractCounters(submissions []CounterTableSubmission, table func(CounterTableSubmission) map[string]int) map[string][]int {
	result := make(map[string][]int)
	for _, sub := range submissions {
		for key, count := range table(sub) {
			result[key] = append(result[key], count)
		}
	}
	return result
}

// extractRiskCalibration extracts risk calibration counters from all submissions.
func extractRiskCalibration(submissions []CounterTableSubmission) map[string][]int {
	return extractCounters(submissions, func(s CounterTableSubmission) map[string]int {
		return s.RiskCalibration
	})
}

// extractFamilyAccuracy extracts family accuracy counters from all submissions.
func extractFamilyAccuracy(submissions []CounterTableSubmission) map[string][]int {
	return extractCounters(submissions, func(s CounterTableSubmission) map[string]int {
		return s.FamilyAccuracy
	})
}

// extractIndicatorUsefulness extracts indicator usefulness counters from all submissions.
func extractIndicatorUsefulness(submissions []CounterTableSubmission) map[string][]int {
	return extractCounters(submissions, func(s CounterTableSubmission) map[string]int {
		return s.IndicatorUseful
	})
}

// extractFamilyConfusion extracts family confusion counters from all submissions.
// Keys with "fb:" prefix are feedback-kind entries; keys with "cf:" prefix
// are corrected-family entries. Both are passed through as-is since the
// prefix distinguishes them.
func extractFamilyConfusion(submissions []CounterTableSubmission) map[string][]int {
	return extractCounters(submissions, func(s CounterTableSubmission) map[string]int {
		return s.FamilyConfusion
	})
}

// extractModelVersionStats extracts model version counters from all submissions.
func extractModelVersionStats(submissions []CounterTableSubmission) map[string][]int {
	return extractCounters(submissions, func(s CounterTableSubmission) map[string]int {
		return s.ModelVersionStats
	})
}

// aggregateTable performs cohort suppression and DP noise on a table.
func aggregateTable(cells map[string][]int, minCohort int, epsilon float64, rng *rand.Rand) map[string]AggregatedCell {
	result := make(map[string]AggregatedCell)

	// Sort keys for deterministic output
	keys := make([]string, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		counts := cells[key]
		deviceCount := len(counts)
		rawCount := 0
		for _, c := range counts {
			rawCount += c
		}

		// Cohort suppression: if fewer than minCohort devices contributed,
		// suppress this cell entirely.
		if deviceCount < minCohort {
			result[key] = AggregatedCell{
				RawCount:    0, // Do not leak counts from suppressed cohorts
				NoisyCount:  0,
				DeviceCount: 0,
				Suppressed:  true,
			}
			continue
		}

		// Apply Laplace noise for DP
		// Sensitivity = 5 (each device can contribute up to 5 per cell,
		// matching the per-cell cap in ContributionLimits)
		// Scale = sensitivity / epsilon
		scale := 5.0 / epsilon
		noise := laplaceNoise(scale, rng)
		noisyCount := float64(rawCount) + noise
		if math.IsInf(noisyCount, 0) || noisyCount < 0 {
			noisyCount = 0
		}

		result[key] = AggregatedCell{
			RawCount:    rawCount,
			NoisyCount:  math.Round(noisyCount*100) / 100, // Round to 2 decimal places
			DeviceCount: deviceCount,
			Suppressed:  false,
		}
	}

	return result
}

// laplaceNoise generates Laplace-distributed noise with the given scale.
func laplaceNoise(scale float64, rng *rand.Rand) float64 {
	u := rng.Float64() - 0.5 // Uniform in [-0.5, 0.5)
	absU := math.Abs(u)
	if absU >= 0.5 {
		absU = 0.4999999999 // Clamp to avoid log(0)
	}
	noise := -scale * math.Log(1-2*absU)
	if u < 0 {
		noise = -noise
	}
	return noise
}

// countSuppressed counts the number of suppressed cells in a table.
func countSuppressed(table map[string]AggregatedCell) int {
	count := 0
	for _, cell := range table {
		if cell.Suppressed {
			count++
		}
	}
	return count
}

// HandleAggregate is the HTTP handler for POST /api/aggregate.
func (a *Aggregator) HandleAggregate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to read body: %s"}`, err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req AggregationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid JSON: %s"}`, err), http.StatusBadRequest)
		return
	}

	if len(req.Submissions) == 0 {
		http.Error(w, `{"error":"no submissions"}`, http.StatusBadRequest)
		return
	}

	response := a.Aggregate(req)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
