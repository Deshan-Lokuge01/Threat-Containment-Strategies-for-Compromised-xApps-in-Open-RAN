package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"
)

type RunRequest struct {
	Scenario         string `json:"scenario"`
	DurationSeconds int    `json:"duration_seconds"`
	ExperimentID    string `json:"experiment_id"`
}

type Status struct {
	Active       bool   `json:"active"`
	Scenario     string `json:"scenario,omitempty"`
	ExperimentID string `json:"experiment_id,omitempty"`
	PID          int    `json:"pid,omitempty"`
	StartedUTC   string `json:"started_utc,omitempty"`
}

var (
	mu     sync.Mutex
	cancel context.CancelFunc
	status Status
)

func tokenOK(r *http.Request) bool {
	expected := os.Getenv("ZTX_ACTUATOR_TOKEN")
	return expected != "" && r.Header.Get("X-ZTX-Token") == expected
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"ok": true,
		"service": "ztx-kpimon-actuator",
		"version": "step48a-dormant",
	})
}

func getStatus(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	writeJSON(w, 200, status)
}

func startRun(w http.ResponseWriter, r *http.Request) {
	if !tokenOK(r) {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}

	var req RunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad_json"})
		return
	}

	if req.Scenario != "R1_CPU_PILOT_SAFE" {
		writeJSON(w, 400, map[string]string{"error": "unsupported_scenario"})
		return
	}
	if req.DurationSeconds <= 0 || req.DurationSeconds > 60 {
		writeJSON(w, 400, map[string]string{"error": "duration_must_be_1_to_60_seconds"})
		return
	}
	if req.ExperimentID == "" {
		writeJSON(w, 400, map[string]string{"error": "experiment_id_required"})
		return
	}

	mu.Lock()
	if status.Active {
		mu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "run_already_active"})
		return
	}

	ctx, c := context.WithTimeout(context.Background(), time.Duration(req.DurationSeconds+5)*time.Second)
	timeoutArg := fmt.Sprintf("%ds", req.DurationSeconds)

	cmd := exec.CommandContext(
		ctx,
		"stress-ng",
		"--cpu", "1",
		"--cpu-load", "20",
		"--timeout", timeoutArg,
		"--metrics-brief",
	)

	if err := cmd.Start(); err != nil {
		mu.Unlock()
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	cancel = c
	status = Status{
		Active: true,
		Scenario: req.Scenario,
		ExperimentID: req.ExperimentID,
		PID: cmd.Process.Pid,
		StartedUTC: time.Now().UTC().Format(time.RFC3339),
	}
	mu.Unlock()

	go func() {
		_ = cmd.Wait()
		mu.Lock()
		status = Status{}
		cancel = nil
		mu.Unlock()
	}()

	writeJSON(w, 202, status)
}

func stopRun(w http.ResponseWriter, r *http.Request) {
	if !tokenOK(r) {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	mu.Lock()
	if cancel != nil {
		cancel()
	}
	status = Status{}
	cancel = nil
	mu.Unlock()
	writeJSON(w, 200, map[string]any{"stopped": true})
}

func main() {
	http.HandleFunc("/ztx-test/v1/health", health)
	http.HandleFunc("/ztx-test/v1/status", getStatus)
	http.HandleFunc("/ztx-test/v1/runs", startRun)
	http.HandleFunc("/ztx-test/v1/stop", stopRun)
	log.Println("ZT-XGuard KPIMON actuator listening on :18080")
	log.Fatal(http.ListenAndServe(":18080", nil))
}
