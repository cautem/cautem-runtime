//go:build !linux

package harden

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cautem/quarshell-core/policy"
)

func TestLandlockCompatibilityModesWhenUnavailable(t *testing.T) {
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{
		IncludeWorkdir:    false,
		IncludeWorkdirSet: true,
	}}
	if got := ModeFromPolicy(doc); got != ModeBestEffort {
		t.Fatalf("default mode = %q, want %q", got, ModeBestEffort)
	}

	var bestEffortLog bytes.Buffer
	result, err := Apply(context.Background(), Options{Doc: doc, Log: &bestEffortLog, NoDrop: true})
	if err != nil {
		t.Fatalf("best_effort Apply() error = %v", err)
	}
	if result.LandlockApplied || result.LandlockError != "" {
		t.Fatalf("best_effort result = %+v, want a no-op without Landlock probe", result)
	}
	if bestEffortLog.Len() != 0 {
		t.Fatalf("best_effort log = %q, want no warning when policy has no paths", bestEffortLog.String())
	}

	doc.Landlock = &policy.Landlock{Compatibility: "hard_requirement"}
	var requiredLog bytes.Buffer
	result, err = Apply(context.Background(), Options{Doc: doc, Log: &requiredLog, NoDrop: true})
	if err == nil {
		t.Fatalf("required Apply() result = %+v, want no-path error", result)
	}
	if !strings.Contains(err.Error(), "hard_requirement") {
		t.Fatalf("required error = %q, want hard_requirement explanation", err)
	}

	doc = policy.Document{}
	var unavailableLog bytes.Buffer
	result, err = Apply(context.Background(), Options{Doc: doc, Log: &unavailableLog, NoDrop: true})
	if err != nil || result.LandlockApplied || result.LandlockError == "" {
		t.Fatalf("best_effort with requested paths = result %+v, error %v; want unavailable but continued", result, err)
	}
	if !strings.Contains(unavailableLog.String(), "mode=best_effort → continue") {
		t.Fatalf("best_effort log = %q, want explicit continue warning", unavailableLog.String())
	}

	doc.Landlock = &policy.Landlock{Compatibility: "hard_requirement"}
	var unavailableRequiredLog bytes.Buffer
	result, err = Apply(context.Background(), Options{Doc: doc, Log: &unavailableRequiredLog, NoDrop: true})
	if err == nil || result.LandlockError == "" {
		t.Fatalf("hard_requirement with requested paths = result %+v, error %v; want unavailable error", result, err)
	}
	if !strings.Contains(unavailableRequiredLog.String(), "mode=required → fail") {
		t.Fatalf("required log = %q, want fail-closed warning", unavailableRequiredLog.String())
	}

	privateDir := t.TempDir()
	var privateDirLog bytes.Buffer
	result, err = Apply(context.Background(), Options{
		Doc:                  policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{}},
		PrivateCredentialDir: privateDir,
		Log:                  &privateDirLog,
		NoDrop:               true,
	})
	if err == nil || result.LandlockError == "" || !strings.Contains(err.Error(), "landlock required") {
		t.Fatalf("private credential isolation = result %+v, error %v; want required Landlock-unavailable error", result, err)
	}
}
