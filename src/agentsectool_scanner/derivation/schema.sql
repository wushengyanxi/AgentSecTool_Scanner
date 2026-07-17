PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS package_snapshots (
    id TEXT PRIMARY KEY,
    package_kind TEXT NOT NULL CHECK (package_kind IN ('source', 'supplement')),
    request_id TEXT,
    task_id TEXT,
    source_path TEXT,
    package_hash TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (request_id, package_kind)
);

CREATE TABLE IF NOT EXISTS derivation_tasks (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    source_package_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN (
        'ready', 'running', 'waiting_user', 'validation_failed',
        'candidate_review', 'admitted', 'discarded', 'infra_failed'
    )),
    project_name TEXT,
    vulnerability_id TEXT,
    current_attempt_id TEXT,
    current_capability_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (source_package_id) REFERENCES package_snapshots(id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('code', 'document', 'auxiliary', 'attachment')),
    relative_path TEXT NOT NULL,
    kind TEXT,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    media_type TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (package_id) REFERENCES package_snapshots(id) ON DELETE CASCADE,
    UNIQUE (package_id, relative_path)
);

CREATE TABLE IF NOT EXISTS agent_threads (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES derivation_tasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_messages (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content TEXT NOT NULL,
    supplement_package_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (thread_id) REFERENCES agent_threads(id) ON DELETE CASCADE,
    FOREIGN KEY (supplement_package_id) REFERENCES package_snapshots(id),
    UNIQUE (thread_id, sequence)
);

CREATE TABLE IF NOT EXISTS agent_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    message_id TEXT,
    event_kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES derivation_tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (message_id) REFERENCES agent_messages(id)
);

CREATE TABLE IF NOT EXISTS agent_runs (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    triggering_message_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'waiting_user', 'failed', 'cancelled')),
    model TEXT NOT NULL,
    response_id TEXT,
    error TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY (task_id) REFERENCES derivation_tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (triggering_message_id) REFERENCES agent_messages(id)
);

CREATE TABLE IF NOT EXISTS acceptance_tests (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    stable_key TEXT NOT NULL,
    current_version INTEGER NOT NULL CHECK (current_version > 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES derivation_tasks(id) ON DELETE CASCADE,
    UNIQUE (task_id, stable_key)
);

CREATE TABLE IF NOT EXISTS acceptance_test_versions (
    id TEXT PRIMARY KEY,
    acceptance_test_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    name TEXT NOT NULL,
    purpose TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    blocking INTEGER NOT NULL CHECK (blocking IN (0, 1)),
    assertion_json TEXT NOT NULL,
    script_artifact_id TEXT,
    user_confirmed INTEGER NOT NULL CHECK (user_confirmed IN (0, 1)),
    actor TEXT NOT NULL CHECK (actor IN ('agent', 'user', 'system')),
    change_reason TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (acceptance_test_id) REFERENCES acceptance_tests(id) ON DELETE CASCADE,
    FOREIGN KEY (script_artifact_id) REFERENCES artifacts(id),
    UNIQUE (acceptance_test_id, version)
);

CREATE TABLE IF NOT EXISTS derivation_attempts (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    agent_run_id TEXT,
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    input_hash TEXT NOT NULL,
    workspace_path TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'validating', 'failed', 'candidate')),
    summary TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES derivation_tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (agent_run_id) REFERENCES agent_runs(id),
    UNIQUE (task_id, ordinal)
);

CREATE TABLE IF NOT EXISTS harness_runs (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider = 'local_docker'),
    status TEXT NOT NULL CHECK (status IN ('running', 'passed', 'failed', 'blocked', 'cancelled')),
    workdir TEXT NOT NULL,
    image_reference TEXT,
    image_digest TEXT,
    error TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY (task_id) REFERENCES derivation_tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (attempt_id) REFERENCES derivation_attempts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS acceptance_results (
    id TEXT PRIMARY KEY,
    harness_run_id TEXT NOT NULL,
    acceptance_test_id TEXT NOT NULL,
    acceptance_test_version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('passed', 'failed', 'blocked')),
    actual_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    failure_kind TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (harness_run_id) REFERENCES harness_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (acceptance_test_id) REFERENCES acceptance_tests(id)
);

CREATE TABLE IF NOT EXISTS capability_packages (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    asset_type TEXT NOT NULL,
    capability_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('candidate', 'admitted', 'rejected', 'superseded')),
    package_path TEXT NOT NULL,
    image_reference TEXT NOT NULL,
    image_digest TEXT,
    manifest_json TEXT NOT NULL,
    review_note TEXT,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    FOREIGN KEY (task_id) REFERENCES derivation_tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (attempt_id) REFERENCES derivation_attempts(id),
    UNIQUE (asset_type, capability_key, version)
);

CREATE TABLE IF NOT EXISTS project_tests (
    id TEXT PRIMARY KEY,
    capability_package_id TEXT NOT NULL,
    stable_key TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    definition_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (capability_package_id) REFERENCES capability_packages(id) ON DELETE CASCADE,
    UNIQUE (capability_package_id, stable_key)
);

CREATE TABLE IF NOT EXISTS vulnerability_rules (
    id TEXT PRIMARY KEY,
    capability_package_id TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    rule_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (capability_package_id) REFERENCES capability_packages(id) ON DELETE CASCADE,
    UNIQUE (capability_package_id, vulnerability_id)
);

CREATE INDEX IF NOT EXISTS idx_tasks_status ON derivation_tasks(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_artifacts_package ON artifacts(package_id, role);
CREATE INDEX IF NOT EXISTS idx_messages_thread ON agent_messages(thread_id, sequence);
CREATE INDEX IF NOT EXISTS idx_events_task ON agent_events(task_id, id);
CREATE INDEX IF NOT EXISTS idx_acceptance_task ON acceptance_tests(task_id, stable_key);
CREATE INDEX IF NOT EXISTS idx_harness_task ON harness_runs(task_id, started_at DESC);
