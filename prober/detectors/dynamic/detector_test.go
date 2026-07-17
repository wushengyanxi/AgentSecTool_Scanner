package dynamic

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wushengyanxi/agentsectool-scanner/prober/detectors"
)

func TestPersistentWorkerServesMultipleTargets(t *testing.T) {
	manifest := Manifest{
		SchemaVersion: "1.0",
		CapabilityID:  "project-x-marker",
		AssetType:     "project-x",
		DefaultPorts:  []uint16{8080},
		Project:       Project{Name: "Project X"},
		ProjectTests: []ProjectTest{{
			TestID: "project-x.marker", Name: "Marker", Description: "Stable marker", Version: 1,
		}},
		IdentityRule: IdentityRule{Operator: "all", Tests: []string{"project-x.marker"}},
		Runtime: Runtime{
			Protocol: protocolVersion, ImageReference: "fixture", ImageDigest: "sha256:fixture",
			MaxWorkers: 1, VersionFact: "version.value",
		},
		DisplayTemplate: map[string]any{"title": "Project X", "facts": []any{"version"}},
	}
	factory := func() *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=TestWorkerHelperProcess", "--")
		cmd.Env = append(os.Environ(), "GO_DYNAMIC_WORKER_HELPER=1")
		return cmd
	}
	detector, err := newDetector(manifest, 4, factory)
	if err != nil {
		t.Fatal(err)
	}
	defer detector.Close()

	var processID string
	for _, host := range []string{"192.0.2.1", "192.0.2.2"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		value, err := detector.Probe(ctx, detectors.Target{Host: host, Port: 8080}, detectors.ProbeOptions{Timeout: time.Second})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		result := value.(Result)
		if !result.IsMatch || result.Category != "confirmed" || result.Version != "1.2.3" {
			t.Fatalf("unexpected result: %+v", result)
		}
		pid := fmt.Sprint(result.Facts["pid"])
		if processID == "" {
			processID = pid
		} else if pid != processID {
			t.Fatalf("worker was not reused: first pid %s, second pid %s", processID, pid)
		}
	}
}

func TestWorkerHelperProcess(t *testing.T) {
	if os.Getenv("GO_DYNAMIC_WORKER_HELPER") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request workerRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			os.Exit(2)
		}
		testID := os.Getenv("GO_DYNAMIC_TEST_ID")
		if testID == "" {
			testID = "project-x.marker"
		}
		version := os.Getenv("GO_DYNAMIC_VERSION")
		if version == "" {
			version = "1.2.3"
		}
		facts := map[string]any{
			"pid": os.Getpid(), "version": map[string]any{"value": version},
		}
		if factKey := os.Getenv("GO_DYNAMIC_FACT_KEY"); factKey != "" {
			facts = map[string]any{factKey: true}
		}
		_ = encoder.Encode(WorkerResponse{
			RequestID: request.RequestID,
			TestID:    testID,
			Status:    "satisfied",
			Facts:     facts,
			Evidence:  []any{map[string]any{"kind": "fixture"}},
		})
	}
	os.Exit(0)
}

func TestCompositeDetectorAggregatesIndependentProjectTests(t *testing.T) {
	children := []*Detector{}
	for _, fixture := range []struct {
		testID  string
		factKey string
	}{
		{testID: "project-x.marker", factKey: "marker"},
		{testID: "project-x.feature", factKey: "feature_enabled"},
	} {
		manifest := Manifest{
			SchemaVersion: "1.0",
			CapabilityID:  fixture.testID,
			AssetType:     "project-x",
			DefaultPorts:  []uint16{8080},
			Project:       Project{Name: "Project X"},
			ProjectTests: []ProjectTest{{
				TestID: fixture.testID, Name: fixture.testID, Description: "Independent fact", Version: 1,
			}},
			IdentityRule:    IdentityRule{Operator: "all", Tests: []string{fixture.testID}},
			Runtime:         Runtime{Protocol: protocolVersion, ImageReference: "fixture", ImageDigest: "sha256:fixture", MaxWorkers: 1},
			DisplayTemplate: map[string]any{"title": fixture.testID, "facts": []any{fixture.factKey}},
		}
		current := fixture
		factory := func() *exec.Cmd {
			cmd := exec.Command(os.Args[0], "-test.run=TestWorkerHelperProcess", "--")
			cmd.Env = append(
				os.Environ(),
				"GO_DYNAMIC_WORKER_HELPER=1",
				"GO_DYNAMIC_TEST_ID="+current.testID,
				"GO_DYNAMIC_FACT_KEY="+current.factKey,
			)
			return cmd
		}
		child, err := newDetector(manifest, 1, factory)
		if err != nil {
			t.Fatal(err)
		}
		children = append(children, child)
	}
	composite := &CompositeDetector{assetType: "project-x", detectors: children, ports: []uint16{8080}}
	defer composite.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	value, err := composite.Probe(
		ctx,
		detectors.Target{Host: "192.0.2.10", Port: 8080},
		detectors.ProbeOptions{Timeout: time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(Result)
	if !result.IsMatch || len(result.TestResults) != 2 || len(result.DisplayTemplates) != 2 {
		t.Fatalf("unexpected aggregate result: %+v", result)
	}
	if result.Facts["marker"] != true || result.Facts["feature_enabled"] != true {
		t.Fatalf("independent facts were not merged: %+v", result.Facts)
	}
}

func TestCompositeDetectorKeepsVersionConflictAfterLaterResult(t *testing.T) {
	children := []*Detector{}
	for index, version := range []string{"1.0.0", "2.0.0", "1.0.0"} {
		testID := fmt.Sprintf("project-x.version-%d", index)
		manifest := Manifest{
			SchemaVersion: "1.0",
			CapabilityID:  testID,
			AssetType:     "project-x",
			DefaultPorts:  []uint16{8080},
			Project:       Project{Name: "Project X"},
			ProjectTests: []ProjectTest{{
				TestID: testID, Name: testID, Description: "Version observation", Version: 1,
			}},
			IdentityRule: IdentityRule{Operator: "all", Tests: []string{testID}},
			Runtime: Runtime{
				Protocol: protocolVersion, ImageReference: "fixture", ImageDigest: "sha256:fixture",
				MaxWorkers: 1, VersionFact: "version.value",
			},
			DisplayTemplate: map[string]any{"title": testID, "facts": []any{"version"}},
		}
		currentTestID, currentVersion := testID, version
		factory := func() *exec.Cmd {
			cmd := exec.Command(os.Args[0], "-test.run=TestWorkerHelperProcess", "--")
			cmd.Env = append(
				os.Environ(),
				"GO_DYNAMIC_WORKER_HELPER=1",
				"GO_DYNAMIC_TEST_ID="+currentTestID,
				"GO_DYNAMIC_VERSION="+currentVersion,
			)
			return cmd
		}
		child, err := newDetector(manifest, 1, factory)
		if err != nil {
			t.Fatal(err)
		}
		children = append(children, child)
	}
	composite := &CompositeDetector{assetType: "project-x", detectors: children}
	defer composite.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	value, err := composite.Probe(
		ctx,
		detectors.Target{Host: "192.0.2.11", Port: 8080},
		detectors.ProbeOptions{Timeout: time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(Result)
	if result.Version != "" || result.VersionSource != "" || !strings.Contains(result.ErrorType, "version_conflict") {
		t.Fatalf("version conflict was not preserved: %+v", result)
	}
}

func TestManifestPathCannotEscapeRegistry(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "outside-capability.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })
	index := indexFile{
		SchemaVersion: "1.0",
		Capabilities: map[string][]indexEntry{
			"project-x": {{ManifestPath: "../" + filepath.Base(outside)}},
		},
	}
	data, _ := json.Marshal(index)
	if err := os.WriteFile(filepath.Join(root, "index.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManifest("project-x", root); err == nil {
		t.Fatal("expected path escape to be rejected")
	}
}

func TestLoadManifestsKeepsMultipleProjectTestsForOneAssetType(t *testing.T) {
	root := t.TempDir()
	entries := []indexEntry{}
	for _, testID := range []string{"project-x.marker", "project-x.version"} {
		capabilityID := testID
		dir := filepath.Join(root, capabilityID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		manifest := Manifest{
			SchemaVersion: "1.0",
			CapabilityID:  capabilityID,
			AssetType:     "project-x",
			DefaultPorts:  []uint16{8080},
			Project:       Project{Name: "Project X"},
			ProjectTests: []ProjectTest{{
				TestID: testID, Name: testID, Description: "Independent project fact", Version: 1,
			}},
			IdentityRule: IdentityRule{Operator: "all", Tests: []string{testID}},
			Runtime: Runtime{
				Protocol: protocolVersion, ImageReference: capabilityID, ImageDigest: "sha256:" + capabilityID,
			},
			VulnerabilityRules: []VulnerabilityRule{{
				VulnerabilityID: "CVE-TEST",
				Condition:       map[string]any{"path": "facts.marker", "operator": "eq", "value": true},
			}},
			DisplayTemplate: map[string]any{"title": testID, "facts": []any{"marker"}},
		}
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		manifestPath := filepath.Join(dir, "capability.json")
		if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, indexEntry{
			CapabilityID: capabilityID,
			ManifestPath: capabilityID + "/capability.json",
			ImageDigest:  manifest.Runtime.ImageDigest,
		})
	}
	index := indexFile{
		SchemaVersion: "1.0",
		Capabilities:  map[string][]indexEntry{"project-x": entries},
	}
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifests, err := loadManifests("project-x", root)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 2 {
		t.Fatalf("expected two manifests, got %d", len(manifests))
	}
}

func TestValidateResponseRejectsMismatchedTest(t *testing.T) {
	response := WorkerResponse{
		RequestID: "r1", TestID: "wrong", Status: "satisfied", Facts: map[string]any{},
	}
	if err := validateResponse(&response, "r1", "expected"); err == nil {
		t.Fatal("expected test id mismatch")
	}
	response.TestID = "expected"
	response.Status = "invalid-" + strconv.Itoa(1)
	if err := validateResponse(&response, "r1", "expected"); err == nil {
		t.Fatal("expected invalid status")
	}
}
