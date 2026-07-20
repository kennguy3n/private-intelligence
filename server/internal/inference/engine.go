// Package inference wraps the Rust zk-ai-core engine via cgo FFI.
//
// The engine is a global singleton initialized once at startup.
// All inference calls go through the C ABI defined in zkai.h.
package inference

/*
#cgo CFLAGS: -I../../crates/go-ffi
#cgo LDFLAGS: -L../../crates/go-ffi/target/release -lzk_ai_go_ffi -lm -ldl -lstdc++

#include <stdlib.h>
#include "zkai.h"

// Note: in production, the static library is built from the Rust crate
// and linked here. For development without the Rust build, the functions
// are stubbed out.
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// Engine wraps the Rust AI inference engine.
type Engine struct {
	initialized bool
}

// TaskResult is the JSON result from an inference task.
type TaskResult struct {
	Output     string `json:"output"`
	Task       string `json:"task"`
	Model      string `json:"model"`
	Adapter    string `json:"adapter"`
	DurationMs uint64 `json:"duration_ms"`
}

// DeviceProfile is the JSON device profile.
type DeviceProfile struct {
	Tier            string `json:"tier"`
	Acceleration    string `json:"acceleration"`
	TotalMemoryMB   uint32 `json:"total_memory_mb"`
	AvailableMemMB  uint32 `json:"available_memory_mb"`
	CPUCores        uint32 `json:"cpu_cores"`
	HasNPU          bool   `json:"has_npu"`
	NPUTops         *uint32 `json:"npu_tops"`
	BatteryLevel    *uint8  `json:"battery_level"`
	ThermalState    string `json:"thermal_state"`
	Platform        string `json:"platform"`
}

// NewEngine initializes the AI inference engine with the given cache directory.
func NewEngine(cacheDir string) (*Engine, error) {
	cCacheDir := C.CString(cacheDir)
	defer C.free(unsafe.Pointer(cCacheDir))

	ret := C.zkai_init(cCacheDir)
	if ret != 0 {
		return nil, fmt.Errorf("zkai_init failed with code %d", ret)
	}

	return &Engine{initialized: true}, nil
}

// Summarize runs a summarization task.
func (e *Engine) Summarize(text, language string) (*TaskResult, error) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))
	cLang := C.CString(language)
	defer C.free(unsafe.Pointer(cLang))

	result := C.zkai_summarize(cText, cLang)
	if result == nil {
		return nil, fmt.Errorf("summarize failed")
	}
	defer C.zkai_free_string(result)

	goResult := C.GoString(result)
	var tr TaskResult
	if err := json.Unmarshal([]byte(goResult), &tr); err != nil {
		return nil, fmt.Errorf("unmarshal result: %w", err)
	}
	return &tr, nil
}

// Translate runs a translation task.
func (e *Engine) Translate(text, sourceLang, targetLang string) (*TaskResult, error) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))
	cSrc := C.CString(sourceLang)
	defer C.free(unsafe.Pointer(cSrc))
	cDst := C.CString(targetLang)
	defer C.free(unsafe.Pointer(cDst))

	result := C.zkai_translate(cText, cSrc, cDst)
	if result == nil {
		return nil, fmt.Errorf("translate failed")
	}
	defer C.zkai_free_string(result)

	goResult := C.GoString(result)
	var tr TaskResult
	if err := json.Unmarshal([]byte(goResult), &tr); err != nil {
		return nil, fmt.Errorf("unmarshal result: %w", err)
	}
	return &tr, nil
}

// KeyPoints runs a key-point extraction task.
func (e *Engine) KeyPoints(text, language string) (*TaskResult, error) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))
	cLang := C.CString(language)
	defer C.free(unsafe.Pointer(cLang))

	result := C.zkai_key_points(cText, cLang)
	if result == nil {
		return nil, fmt.Errorf("key_points failed")
	}
	defer C.zkai_free_string(result)

	goResult := C.GoString(result)
	var tr TaskResult
	if err := json.Unmarshal([]byte(goResult), &tr); err != nil {
		return nil, fmt.Errorf("unmarshal result: %w", err)
	}
	return &tr, nil
}

// DeviceProfile returns the server's device profile.
func (e *Engine) DeviceProfile() (*DeviceProfile, error) {
	result := C.zkai_device_profile()
	if result == nil {
		return nil, fmt.Errorf("device_profile failed")
	}
	defer C.zkai_free_string(result)

	goResult := C.GoString(result)
	var dp DeviceProfile
	if err := json.Unmarshal([]byte(goResult), &dp); err != nil {
		return nil, fmt.Errorf("unmarshal profile: %w", err)
	}
	return &dp, nil
}

// Shutdown releases all engine resources.
func (e *Engine) Shutdown() {
	if e.initialized {
		C.zkai_shutdown()
		e.initialized = false
	}
}
