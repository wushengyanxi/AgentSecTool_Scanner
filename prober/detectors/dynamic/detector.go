// Package dynamic loads admitted, language-agnostic detector workers.
package dynamic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wushengyanxi/agentsectool-scanner/prober/detectors"
)

const protocolVersion = "jsonl-v1"

type indexFile struct {
	SchemaVersion string                  `json:"schema_version"`
	Capabilities  map[string][]indexEntry `json:"capabilities"`
}

type rawIndexFile struct {
	SchemaVersion string                     `json:"schema_version"`
	Capabilities  map[string]json.RawMessage `json:"capabilities"`
}

type indexEntry struct {
	CapabilityID string `json:"capability_id"`
	ManifestPath string `json:"manifest_path"`
	ImageDigest  string `json:"image_digest"`
}

type Manifest struct {
	SchemaVersion      string              `json:"schema_version"`
	CapabilityID       string              `json:"capability_id"`
	AssetType          string              `json:"asset_type"`
	DefaultPorts       []uint16            `json:"default_ports"`
	Project            Project             `json:"project"`
	ProjectTests       []ProjectTest       `json:"project_tests"`
	IdentityRule       IdentityRule        `json:"identity_rule"`
	Runtime            Runtime             `json:"runtime"`
	VulnerabilityRules []VulnerabilityRule `json:"vulnerability_rules"`
	DisplayTemplate    map[string]any      `json:"display_template"`
}

type Project struct {
	Name string `json:"name"`
}

type ProjectTest struct {
	TestID      string `json:"test_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     int    `json:"version"`
}

type IdentityRule struct {
	Operator string   `json:"operator"`
	Tests    []string `json:"tests"`
}

type Runtime struct {
	Protocol       string `json:"protocol"`
	ImageReference string `json:"image_reference"`
	ImageDigest    string `json:"image_digest"`
	MaxWorkers     int    `json:"max_workers"`
	VersionFact    string `json:"version_fact"`
}

type VulnerabilityRule struct {
	VulnerabilityID string         `json:"vulnerability_id"`
	Condition       map[string]any `json:"condition"`
}

type workerRequest struct {
	RequestID string       `json:"request_id"`
	Target    workerTarget `json:"target"`
	TimeoutMS int64        `json:"timeout_ms"`
}

type workerTarget struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	TLS  bool   `json:"tls"`
}

type WorkerResponse struct {
	RequestID string         `json:"request_id"`
	TestID    string         `json:"test_id"`
	Status    string         `json:"status"`
	Facts     map[string]any `json:"facts"`
	Evidence  []any          `json:"evidence"`
	Error     any            `json:"error"`
}

type Result struct {
	AssetType          string              `json:"asset_type"`
	Detector           string              `json:"detector"`
	IP                 string              `json:"ip"`
	Port               uint16              `json:"port"`
	TLS                bool                `json:"tls"`
	TS                 string              `json:"ts"`
	IsMatch            bool                `json:"is_match"`
	IsOpenClaw         bool                `json:"is_openclaw"`
	Category           string              `json:"category,omitempty"`
	Rule               string              `json:"rule,omitempty"`
	Version            string              `json:"version,omitempty"`
	VersionSource      string              `json:"version_source,omitempty"`
	Matched            []string            `json:"matched"`
	ErrorType          string              `json:"error_type,omitempty"`
	Facts              map[string]any      `json:"facts"`
	TestResults        []WorkerResponse    `json:"test_results"`
	VulnerabilityRules []VulnerabilityRule `json:"vulnerability_rules,omitempty"`
	DisplayTemplates   []map[string]any    `json:"display_templates,omitempty"`
}

func (r Result) DetectorSummary() detectors.Summary {
	return detectors.Summary{
		AssetType: r.AssetType,
		Detector:  r.Detector,
		IP:        r.IP,
		Port:      r.Port,
		IsMatch:   r.IsMatch,
		Category:  r.Category,
		Version:   r.Version,
		Matched:   r.Matched,
		ErrorType: r.ErrorType,
	}
}

type commandFactory func() *exec.Cmd

type processWorker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	stderr *bytes.Buffer
}

type Detector struct {
	manifest Manifest
	factory  commandFactory
	pool     chan *processWorker
	closed   atomic.Bool
	seq      atomic.Uint64
	mu       sync.Mutex
	workers  map[*processWorker]struct{}
}

// CompositeDetector executes every admitted project test registered for one asset type.
type CompositeDetector struct {
	assetType string
	detectors []*Detector
	ports     []uint16
}

func New(assetType, registryRoot string, concurrency int) (*CompositeDetector, error) {
	manifests, err := loadManifests(assetType, registryRoot)
	if err != nil {
		return nil, err
	}
	composite := &CompositeDetector{assetType: assetType}
	portSet := map[uint16]struct{}{}
	for _, manifest := range manifests {
		if err := verifyImage(manifest.Runtime.ImageReference, manifest.Runtime.ImageDigest); err != nil {
			_ = composite.Close()
			return nil, fmt.Errorf("verify %s: %w", manifest.CapabilityID, err)
		}
		current := manifest
		factory := func() *exec.Cmd {
			return exec.Command(
				"docker", "run", "--rm", "-i",
				"--network", "bridge",
				"--read-only",
				"--cap-drop=ALL",
				"--security-opt=no-new-privileges",
				"--pids-limit=64",
				"--memory=256m",
				"--cpus=1",
				"--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
				"--env=PYTHONDONTWRITEBYTECODE=1",
				current.Runtime.ImageReference,
			)
		}
		detector, err := newDetector(current, concurrency, factory)
		if err != nil {
			_ = composite.Close()
			return nil, err
		}
		composite.detectors = append(composite.detectors, detector)
		for _, port := range current.DefaultPorts {
			portSet[port] = struct{}{}
		}
	}
	for port := range portSet {
		composite.ports = append(composite.ports, port)
	}
	sort.Slice(composite.ports, func(i, j int) bool { return composite.ports[i] < composite.ports[j] })
	return composite, nil
}

func newDetector(manifest Manifest, concurrency int, factory commandFactory) (*Detector, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	workers := manifest.Runtime.MaxWorkers
	if workers <= 0 {
		workers = 4
	}
	if concurrency > 0 && workers > concurrency {
		workers = concurrency
	}
	if workers < 1 {
		workers = 1
	}
	d := &Detector{
		manifest: manifest,
		factory:  factory,
		pool:     make(chan *processWorker, workers),
		workers:  make(map[*processWorker]struct{}),
	}
	for range workers {
		w, err := d.startWorker()
		if err != nil {
			_ = d.Close()
			return nil, fmt.Errorf("start dynamic worker: %w", err)
		}
		d.pool <- w
	}
	return d, nil
}

func (d *CompositeDetector) Type() string { return d.assetType }
func (d *CompositeDetector) Name() string { return "dynamic/" + d.assetType }
func (d *CompositeDetector) DefaultPorts() []uint16 {
	return append([]uint16(nil), d.ports...)
}

func (d *CompositeDetector) Probe(ctx context.Context, target detectors.Target, opts detectors.ProbeOptions) (any, error) {
	result := Result{
		AssetType:        d.assetType,
		Detector:         d.Name(),
		IP:               target.Host,
		Port:             target.Port,
		TLS:              target.TLS,
		TS:               time.Now().UTC().Format(time.RFC3339),
		Matched:          []string{},
		Facts:            map[string]any{},
		TestResults:      []WorkerResponse{},
		DisplayTemplates: []map[string]any{},
	}
	ruleSeen := map[string]bool{}
	errorsSeen := map[string]bool{}
	factConflicts := map[string][]any{}
	for _, child := range d.detectors {
		value, err := child.Probe(ctx, target, opts)
		if err != nil {
			return result, err
		}
		current := value.(Result)
		result.TestResults = append(result.TestResults, current.TestResults...)
		result.Matched = append(result.Matched, current.Matched...)
		result.DisplayTemplates = append(result.DisplayTemplates, current.DisplayTemplates...)
		for _, rule := range current.VulnerabilityRules {
			encoded, _ := json.Marshal(rule)
			key := string(encoded)
			if !ruleSeen[key] {
				ruleSeen[key] = true
				result.VulnerabilityRules = append(result.VulnerabilityRules, rule)
			}
		}
		for key, value := range current.Facts {
			if conflicts, exists := factConflicts[key]; exists {
				factConflicts[key] = append(conflicts, value)
				continue
			}
			previous, exists := result.Facts[key]
			if !exists {
				result.Facts[key] = value
				continue
			}
			if !reflect.DeepEqual(previous, value) {
				factConflicts[key] = []any{previous, value}
				delete(result.Facts, key)
			}
		}
		if current.IsMatch {
			result.IsMatch = true
		}
		if current.Version != "" {
			if errorsSeen["version_conflict"] {
				continue
			}
			if result.Version == "" {
				result.Version = current.Version
				result.VersionSource = current.VersionSource
			} else if result.Version != current.Version {
				errorsSeen["version_conflict"] = true
				result.Version = ""
				result.VersionSource = ""
			}
		}
		if current.ErrorType != "" {
			errorsSeen[current.ErrorType] = true
		}
	}
	if len(factConflicts) > 0 {
		result.Facts["_conflicts"] = factConflicts
		errorsSeen["fact_conflict"] = true
	}
	if result.IsMatch {
		result.Category = "confirmed_no_version"
		result.Rule = "any(" + strings.Join(result.Matched, ",") + ")"
		if result.Version != "" {
			result.Category = "confirmed"
		}
	}
	if len(errorsSeen) > 0 {
		kinds := make([]string, 0, len(errorsSeen))
		for kind := range errorsSeen {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		result.ErrorType = strings.Join(kinds, ",")
	}
	return result, nil
}

func (d *CompositeDetector) Close() error {
	var failures []error
	for _, child := range d.detectors {
		if err := child.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (d *Detector) Type() string { return d.manifest.AssetType }
func (d *Detector) Name() string { return d.manifest.CapabilityID }
func (d *Detector) DefaultPorts() []uint16 {
	return append([]uint16(nil), d.manifest.DefaultPorts...)
}

func (d *Detector) Probe(ctx context.Context, target detectors.Target, opts detectors.ProbeOptions) (any, error) {
	result := Result{
		AssetType:          d.manifest.AssetType,
		Detector:           d.manifest.CapabilityID,
		IP:                 target.Host,
		Port:               target.Port,
		TLS:                target.TLS,
		TS:                 time.Now().UTC().Format(time.RFC3339),
		Matched:            []string{},
		Facts:              map[string]any{},
		VulnerabilityRules: d.manifest.VulnerabilityRules,
		DisplayTemplates:   []map[string]any{displayTemplate(d.manifest)},
	}
	if d.closed.Load() {
		return result, errors.New("dynamic detector is closed")
	}
	var worker *processWorker
	select {
	case worker = <-d.pool:
	case <-ctx.Done():
		result.ErrorType = "timeout"
		return result, nil
	}
	if worker == nil {
		var err error
		worker, err = d.startWorker()
		if err != nil {
			d.returnWorker(nil)
			result.ErrorType = "worker_unavailable"
			return result, nil
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	requestID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), d.seq.Add(1))
	req := workerRequest{
		RequestID: requestID,
		Target:    workerTarget{Host: target.Host, Port: target.Port, TLS: target.TLS},
		TimeoutMS: timeout.Milliseconds(),
	}
	type outcome struct {
		response WorkerResponse
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		if err := writeJSONLine(worker.stdin, req); err != nil {
			done <- outcome{err: err}
			return
		}
		line, err := worker.reader.ReadBytes('\n')
		if err != nil {
			done <- outcome{err: err}
			return
		}
		var response WorkerResponse
		if err := json.Unmarshal(line, &response); err != nil {
			done <- outcome{err: fmt.Errorf("decode worker response: %w", err)}
			return
		}
		done <- outcome{response: response}
	}()

	select {
	case <-ctx.Done():
		d.replaceWorker(worker)
		result.ErrorType = "timeout"
		return result, nil
	case out := <-done:
		if out.err != nil {
			d.replaceWorker(worker)
			result.ErrorType = "worker_failed"
			return result, nil
		}
		if err := validateResponse(&out.response, requestID, d.manifest.ProjectTests[0].TestID); err != nil {
			d.replaceWorker(worker)
			result.ErrorType = "protocol_error"
			return result, nil
		}
		d.returnWorker(worker)
		result.TestResults = []WorkerResponse{out.response}
		result.Facts = out.response.Facts
		switch out.response.Status {
		case "satisfied":
			result.Matched = []string{out.response.TestID}
			result.IsMatch = identitySatisfied(d.manifest.IdentityRule, result.Matched)
			if result.IsMatch {
				result.Category = "confirmed_no_version"
				result.Rule = fmt.Sprintf("%s(%s)", d.manifest.IdentityRule.Operator, strings.Join(d.manifest.IdentityRule.Tests, ","))
			}
		case "unknown":
			result.ErrorType = "test_unknown"
		case "error":
			result.ErrorType = "test_error"
		}
		if d.manifest.Runtime.VersionFact != "" {
			if version, ok := factString(out.response.Facts, d.manifest.Runtime.VersionFact); ok {
				result.Version = version
				result.VersionSource = out.response.TestID
				if result.IsMatch {
					result.Category = "confirmed"
				}
			}
		}
		return result, nil
	}
}

func (d *Detector) startWorker() (*processWorker, error) {
	if d.closed.Load() {
		return nil, errors.New("detector closed")
	}
	cmd := d.factory()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, err
	}
	w := &processWorker{cmd: cmd, stdin: stdin, reader: bufio.NewReader(stdout), stderr: stderr}
	d.mu.Lock()
	d.workers[w] = struct{}{}
	d.mu.Unlock()
	return w, nil
}

func (d *Detector) stopWorker(w *processWorker) {
	if w == nil {
		return
	}
	_ = w.stdin.Close()
	if w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
	_ = w.cmd.Wait()
	d.mu.Lock()
	delete(d.workers, w)
	d.mu.Unlock()
}

func (d *Detector) replaceWorker(w *processWorker) {
	d.stopWorker(w)
	if d.closed.Load() {
		return
	}
	replacement, err := d.startWorker()
	if err != nil {
		d.returnWorker(nil)
		return
	}
	d.returnWorker(replacement)
}

func (d *Detector) returnWorker(w *processWorker) {
	if d.closed.Load() {
		d.stopWorker(w)
		return
	}
	d.pool <- w
}

func (d *Detector) Close() error {
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	d.mu.Lock()
	workers := make([]*processWorker, 0, len(d.workers))
	for w := range d.workers {
		workers = append(workers, w)
	}
	d.mu.Unlock()
	for _, w := range workers {
		d.stopWorker(w)
	}
	return nil
}

func Types(registryRoot string) ([]string, error) {
	index, _, err := readIndex(registryRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	types := make([]string, 0, len(index.Capabilities))
	for assetType := range index.Capabilities {
		types = append(types, assetType)
	}
	sort.Strings(types)
	return types, nil
}

func loadManifest(assetType, registryRoot string) (Manifest, error) {
	manifests, err := loadManifests(assetType, registryRoot)
	if err != nil {
		return Manifest{}, err
	}
	return manifests[0], nil
}

func loadManifests(assetType, registryRoot string) ([]Manifest, error) {
	index, root, err := readIndex(registryRoot)
	if err != nil {
		return nil, err
	}
	entries, ok := index.Capabilities[assetType]
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("unknown dynamic asset type %q", assetType)
	}
	manifests := make([]Manifest, 0, len(entries))
	capabilities := map[string]bool{}
	tests := map[string]bool{}
	vulnerabilityRules := map[string]string{}
	for _, entry := range entries {
		path, err := safeManifestPath(root, entry.ManifestPath)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var manifest Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			return nil, fmt.Errorf("decode capability manifest: %w", err)
		}
		if err := validateManifest(manifest); err != nil {
			return nil, fmt.Errorf("validate %s: %w", manifest.CapabilityID, err)
		}
		if manifest.AssetType != assetType {
			return nil, fmt.Errorf("capability index type %q does not match manifest type %q", assetType, manifest.AssetType)
		}
		if entry.CapabilityID != "" && entry.CapabilityID != manifest.CapabilityID {
			return nil, errors.New("capability index id does not match manifest")
		}
		if entry.ImageDigest != "" && entry.ImageDigest != manifest.Runtime.ImageDigest {
			return nil, errors.New("capability index image digest does not match manifest")
		}
		if capabilities[manifest.CapabilityID] {
			return nil, fmt.Errorf("duplicate capability id %q", manifest.CapabilityID)
		}
		capabilities[manifest.CapabilityID] = true
		testID := manifest.ProjectTests[0].TestID
		if tests[testID] {
			return nil, fmt.Errorf("duplicate project test id %q", testID)
		}
		tests[testID] = true
		for _, rule := range manifest.VulnerabilityRules {
			condition, _ := json.Marshal(rule.Condition)
			if previous, exists := vulnerabilityRules[rule.VulnerabilityID]; exists && previous != string(condition) {
				return nil, fmt.Errorf("conflicting rules for vulnerability %q", rule.VulnerabilityID)
			}
			vulnerabilityRules[rule.VulnerabilityID] = string(condition)
		}
		manifests = append(manifests, manifest)
	}
	return manifests, nil
}

func readIndex(registryRoot string) (indexFile, string, error) {
	root, err := filepath.Abs(registryRoot)
	if err != nil {
		return indexFile{}, "", err
	}
	data, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		return indexFile{}, root, err
	}
	var raw rawIndexFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return indexFile{}, root, fmt.Errorf("decode capability index: %w", err)
	}
	if raw.SchemaVersion != "1.0" || raw.Capabilities == nil {
		return indexFile{}, root, errors.New("unsupported capability index")
	}
	index := indexFile{SchemaVersion: raw.SchemaVersion, Capabilities: map[string][]indexEntry{}}
	for assetType, encoded := range raw.Capabilities {
		var entries []indexEntry
		if err := json.Unmarshal(encoded, &entries); err != nil {
			var legacy indexEntry
			if legacyErr := json.Unmarshal(encoded, &legacy); legacyErr != nil {
				return indexFile{}, root, fmt.Errorf("decode capability index entry %q: %w", assetType, err)
			}
			entries = []indexEntry{legacy}
		}
		if len(entries) == 0 {
			return indexFile{}, root, fmt.Errorf("capability index entry %q is empty", assetType)
		}
		index.Capabilities[assetType] = entries
	}
	return index, root, nil
}

func safeManifestPath(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", errors.New("capability manifest path must be relative")
	}
	clean := filepath.Clean(filepath.FromSlash(relative))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("capability manifest path escapes registry root")
	}
	path := filepath.Join(root, clean)
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(realRoot, realPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("capability manifest resolves outside registry root")
	}
	return realPath, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != "1.0" || manifest.AssetType == "" || manifest.CapabilityID == "" {
		return errors.New("invalid capability identity")
	}
	if len(manifest.DefaultPorts) == 0 || len(manifest.ProjectTests) != 1 {
		return errors.New("dynamic capability requires ports and exactly one project test")
	}
	if manifest.ProjectTests[0].TestID == "" {
		return errors.New("project test id is empty")
	}
	if manifest.Runtime.Protocol != protocolVersion || manifest.Runtime.ImageReference == "" || manifest.Runtime.ImageDigest == "" {
		return errors.New("invalid dynamic worker runtime")
	}
	if manifest.IdentityRule.Operator != "all" && manifest.IdentityRule.Operator != "any" {
		return errors.New("identity rule operator must be all or any")
	}
	if len(manifest.IdentityRule.Tests) == 0 {
		return errors.New("identity rule has no project tests")
	}
	if manifest.DisplayTemplate == nil {
		return errors.New("display template is missing")
	}
	return nil
}

func displayTemplate(manifest Manifest) map[string]any {
	template := make(map[string]any, len(manifest.DisplayTemplate)+2)
	for key, value := range manifest.DisplayTemplate {
		template[key] = value
	}
	template["_capability_id"] = manifest.CapabilityID
	template["_project_test_id"] = manifest.ProjectTests[0].TestID
	return template
}

func verifyImage(reference, expectedDigest string) error {
	output, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", reference).CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect worker image: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if strings.TrimSpace(string(output)) != expectedDigest {
		return fmt.Errorf("worker image digest mismatch: expected %s, got %s", expectedDigest, strings.TrimSpace(string(output)))
	}
	return nil
}

func writeJSONLine(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

func validateResponse(response *WorkerResponse, requestID, testID string) error {
	if response.RequestID != requestID {
		return errors.New("worker response request_id mismatch")
	}
	if response.TestID != testID {
		return errors.New("worker response test_id mismatch")
	}
	switch response.Status {
	case "satisfied", "not_satisfied", "unknown", "error":
	default:
		return fmt.Errorf("invalid worker status %q", response.Status)
	}
	if response.Facts == nil {
		response.Facts = map[string]any{}
	}
	if response.Evidence == nil {
		response.Evidence = []any{}
	}
	return nil
}

func identitySatisfied(rule IdentityRule, matched []string) bool {
	hits := make(map[string]bool, len(matched))
	for _, testID := range matched {
		hits[testID] = true
	}
	if rule.Operator == "any" {
		for _, testID := range rule.Tests {
			if hits[testID] {
				return true
			}
		}
		return false
	}
	for _, testID := range rule.Tests {
		if !hits[testID] {
			return false
		}
	}
	return true
}

func factString(facts map[string]any, path string) (string, bool) {
	var current any = facts
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		current, ok = object[part]
		if !ok {
			return "", false
		}
	}
	value, ok := current.(string)
	return value, ok && value != ""
}
