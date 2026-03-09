use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin};
use tokio::sync::{Mutex, Notify};

/// Maximum number of concurrent background processes.
const MAX_CONCURRENT: usize = 5;
/// Maximum pending (unpolled) output buffer per session in bytes (30KB).
const PENDING_OUTPUT_CAP: usize = 30 * 1024;
/// Maximum aggregated (total) output buffer per session in bytes (200KB).
const AGGREGATED_OUTPUT_CAP: usize = 200 * 1024;
/// Maximum tail output in characters for quick status display.
const TAIL_OUTPUT_CHARS: usize = 2000;
/// TTL for exited sessions before automatic cleanup (30 minutes).
const SESSION_TTL_SECS: u64 = 30 * 60;
/// Sweeper interval (TTL / 6 = 5 minutes).
const SWEEPER_INTERVAL_SECS: u64 = SESSION_TTL_SECS / 6;

/// Result of polling a background process.
#[derive(Debug)]
pub struct PollResult {
    pub new_output: String,
    pub is_running: bool,
    pub exit_code: Option<i32>,
}

/// Summary of a background process for listing.
#[derive(Debug, Clone)]
pub struct ProcessSummary {
    pub session_id: String,
    pub pid: u32,
    pub command: String,
    pub started_at: Instant,
    pub is_running: bool,
    pub exit_code: Option<i32>,
    pub scope_key: Option<String>,
}

/// A single background process session.
pub struct ProcessSession {
    pub session_id: String,
    pub pid: u32,
    pub command: String,
    pub started_at: Instant,
    pub exit_code: Option<i32>,
    exited_at: Option<Instant>,
    pending_output: Vec<u8>,
    aggregated_output: Vec<u8>,
    tail_output: String,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    scope_key: Option<String>,
    output_notify: Arc<Notify>,
}

/// Check if a session matches the requested scope.
/// `None` scope means "unscoped access" (matches everything).
fn scope_matches(session: &ProcessSession, scope: Option<&str>) -> bool {
    match scope {
        None => true,
        Some(s) => session.scope_key.as_deref() == Some(s),
    }
}

/// Registry for background OS processes, following the SubagentRegistry pattern.
#[derive(Clone)]
pub struct ProcessRegistry {
    sessions: Arc<Mutex<HashMap<String, ProcessSession>>>,
}

impl ProcessRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start the background TTL sweeper task.
    pub fn start_sweeper(&self) {
        let registry = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(SWEEPER_INTERVAL_SECS)).await;
                registry
                    .sweep_expired(Duration::from_secs(SESSION_TTL_SECS))
                    .await;
            }
        });
    }

    /// Remove exited sessions older than `ttl`.
    pub async fn sweep_expired(&self, ttl: Duration) {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, s| match s.exited_at {
            Some(t) => t.elapsed() < ttl,
            None => true,
        });
    }

    /// Check if we can spawn another background process.
    pub async fn can_spawn(&self) -> bool {
        let sessions = self.sessions.lock().await;
        sessions.values().filter(|s| s.exit_code.is_none()).count() < MAX_CONCURRENT
    }

    /// Register a new background process session.
    pub async fn register(&self, session: ProcessSession) {
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session.session_id.clone(), session);
    }

    /// Poll a session for new output since last poll.
    pub async fn poll(&self, id: &str) -> Option<PollResult> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions.get_mut(id)?;

        let new_output = String::from_utf8_lossy(&session.pending_output).to_string();
        session.pending_output.clear();

        Some(PollResult {
            new_output,
            is_running: session.exit_code.is_none(),
            exit_code: session.exit_code,
        })
    }

    /// Poll with scope filtering. Returns None if session doesn't exist or scope mismatches.
    pub async fn poll_scoped(&self, id: &str, scope: Option<&str>) -> Option<PollResult> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions.get_mut(id)?;
        if !scope_matches(session, scope) {
            return None;
        }
        let new_output = String::from_utf8_lossy(&session.pending_output).to_string();
        session.pending_output.clear();
        Some(PollResult {
            new_output,
            is_running: session.exit_code.is_none(),
            exit_code: session.exit_code,
        })
    }

    /// Long-poll: wait for new output or timeout.
    pub async fn poll_wait(&self, id: &str, timeout: Duration) -> Option<PollResult> {
        let notify = {
            let sessions = self.sessions.lock().await;
            let session = sessions.get(id)?;
            if !session.pending_output.is_empty() || session.exit_code.is_some() {
                drop(sessions);
                return self.poll(id).await;
            }
            session.output_notify.clone()
        };
        // Lock released — safe to await without deadlock.
        let _ = tokio::time::timeout(timeout, notify.notified()).await;
        self.poll(id).await
    }

    /// Kill a background process and its entire process group.
    pub async fn kill(&self, id: &str) -> anyhow::Result<()> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("No session with id '{id}'"))?;

        if let Some(mut child) = session.child.take() {
            crate::runtime::process_kill::kill_process_tree(
                &mut child,
                std::time::Duration::from_secs(3),
            )
            .await;
            if session.exit_code.is_none() {
                session.exit_code = Some(-1);
                session.exited_at = Some(Instant::now());
                session.output_notify.notify_waiters();
            }
        }
        Ok(())
    }

    /// Kill with scope checking. Returns error if scope mismatches.
    pub async fn kill_scoped(&self, id: &str, scope: Option<&str>) -> anyhow::Result<()> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("No session with id '{id}'"))?;
        if !scope_matches(session, scope) {
            anyhow::bail!("Scope mismatch for session '{id}'");
        }
        if let Some(mut child) = session.child.take() {
            crate::runtime::process_kill::kill_process_tree(
                &mut child,
                std::time::Duration::from_secs(3),
            )
            .await;
            if session.exit_code.is_none() {
                session.exit_code = Some(-1);
                session.exited_at = Some(Instant::now());
                session.output_notify.notify_waiters();
            }
        }
        Ok(())
    }

    /// List all sessions.
    pub async fn list(&self) -> Vec<ProcessSummary> {
        let sessions = self.sessions.lock().await;
        sessions
            .values()
            .map(|s| ProcessSummary {
                session_id: s.session_id.clone(),
                pid: s.pid,
                command: s.command.clone(),
                started_at: s.started_at,
                is_running: s.exit_code.is_none(),
                exit_code: s.exit_code,
                scope_key: s.scope_key.clone(),
            })
            .collect()
    }

    /// List sessions filtered by scope.
    pub async fn list_scoped(&self, scope: Option<&str>) -> Vec<ProcessSummary> {
        let sessions = self.sessions.lock().await;
        sessions
            .values()
            .filter(|s| scope_matches(s, scope))
            .map(|s| ProcessSummary {
                session_id: s.session_id.clone(),
                pid: s.pid,
                command: s.command.clone(),
                started_at: s.started_at,
                is_running: s.exit_code.is_none(),
                exit_code: s.exit_code,
                scope_key: s.scope_key.clone(),
            })
            .collect()
    }

    /// List only active (running) sessions.
    pub async fn list_active(&self) -> Vec<ProcessSummary> {
        self.list()
            .await
            .into_iter()
            .filter(|s| s.is_running)
            .collect()
    }

    /// Read the full aggregated output log for a session.
    pub async fn read_log(&self, id: &str) -> Option<String> {
        let sessions = self.sessions.lock().await;
        let session = sessions.get(id)?;
        Some(String::from_utf8_lossy(&session.aggregated_output).to_string())
    }

    /// Read log with scope filtering.
    pub async fn read_log_scoped(&self, id: &str, scope: Option<&str>) -> Option<String> {
        let sessions = self.sessions.lock().await;
        let session = sessions.get(id)?;
        if !scope_matches(session, scope) {
            return None;
        }
        Some(String::from_utf8_lossy(&session.aggregated_output).to_string())
    }

    /// Read log with byte-level pagination.
    pub async fn read_log_paginated(
        &self,
        id: &str,
        offset: usize,
        limit: usize,
    ) -> Option<(String, usize)> {
        let sessions = self.sessions.lock().await;
        let session = sessions.get(id)?;
        let total_bytes = session.aggregated_output.len();
        if offset >= total_bytes {
            return Some((String::new(), total_bytes));
        }
        let end = (offset + limit).min(total_bytes);
        let slice = &session.aggregated_output[offset..end];
        Some((String::from_utf8_lossy(slice).to_string(), total_bytes))
    }

    /// Read the tail output for quick display.
    pub async fn read_tail(&self, id: &str) -> Option<String> {
        let sessions = self.sessions.lock().await;
        let session = sessions.get(id)?;
        Some(session.tail_output.clone())
    }

    /// Append bytes to a buffer, keeping only the last `cap` bytes.
    fn append_capped(buf: &mut Vec<u8>, bytes: &[u8], cap: usize) {
        if bytes.len() >= cap {
            // Incoming data alone exceeds cap — keep only the tail.
            buf.clear();
            buf.extend_from_slice(&bytes[bytes.len() - cap..]);
        } else {
            let total = buf.len() + bytes.len();
            if total > cap {
                let drain = total - cap;
                buf.drain(..drain);
            }
            buf.extend_from_slice(bytes);
        }
    }

    /// Append new output bytes from the background reader task.
    pub async fn append_output(&self, id: &str, bytes: &[u8]) {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(id) {
            // Pending buffer: keep only the last PENDING_OUTPUT_CAP bytes.
            Self::append_capped(&mut session.pending_output, bytes, PENDING_OUTPUT_CAP);

            // Aggregated buffer: keep only the last AGGREGATED_OUTPUT_CAP bytes.
            Self::append_capped(&mut session.aggregated_output, bytes, AGGREGATED_OUTPUT_CAP);

            // Tail output: append and trim to last N chars.
            let text = String::from_utf8_lossy(bytes);
            session.tail_output.push_str(&text);
            if session.tail_output.len() > TAIL_OUTPUT_CHARS {
                let mut start = session.tail_output.len() - TAIL_OUTPUT_CHARS;
                // Advance to a char boundary (MSRV-compatible fallback for ceil_char_boundary).
                while !session.tail_output.is_char_boundary(start)
                    && start < session.tail_output.len()
                {
                    start += 1;
                }
                session.tail_output = session.tail_output[start..].to_string();
            }

            // Wake any long-poll waiters.
            session.output_notify.notify_waiters();
        }
    }

    /// Mark a session as exited with the given code.
    pub async fn mark_exited(&self, id: &str, code: i32) {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(id) {
            session.exit_code = Some(code);
            session.exited_at = Some(Instant::now());
            // Drop the child handle since it's no longer needed.
            session.child.take();
            // Wake any long-poll waiters.
            session.output_notify.notify_waiters();
        }
    }

    /// Write bytes to a session's stdin.
    pub async fn write_stdin(&self, id: &str, data: &[u8]) -> anyhow::Result<()> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("No session with id '{id}'"))?;
        let stdin = session
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No stdin available for session '{id}'"))?;
        stdin.write_all(data).await?;
        Ok(())
    }
}

impl ProcessSession {
    pub fn new(session_id: String, pid: u32, command: String, mut child: Child) -> Self {
        let stdin = child.stdin.take();
        Self {
            session_id,
            pid,
            command,
            started_at: Instant::now(),
            exit_code: None,
            exited_at: None,
            pending_output: Vec::new(),
            aggregated_output: Vec::new(),
            tail_output: String::new(),
            child: Some(child),
            stdin,
            scope_key: None,
            output_notify: Arc::new(Notify::new()),
        }
    }

    /// Set the scope key for agent isolation.
    pub fn with_scope_key(mut self, scope_key: Option<String>) -> Self {
        self.scope_key = scope_key;
        self
    }

    /// Test-only constructor without a real Child handle.
    #[cfg(test)]
    pub(crate) fn new_test(session_id: String, pid: u32, command: String) -> Self {
        Self {
            session_id,
            pid,
            command,
            started_at: Instant::now(),
            exit_code: None,
            exited_at: None,
            pending_output: Vec::new(),
            aggregated_output: Vec::new(),
            tail_output: String::new(),
            child: None,
            stdin: None,
            scope_key: None,
            output_notify: Arc::new(Notify::new()),
        }
    }

    /// Test-only constructor for an already-exited session.
    #[cfg(test)]
    pub(crate) fn new_test_exited(
        session_id: String,
        pid: u32,
        command: String,
        exit_code: i32,
    ) -> Self {
        Self {
            session_id,
            pid,
            command,
            started_at: Instant::now(),
            exit_code: Some(exit_code),
            exited_at: Some(Instant::now()),
            pending_output: Vec::new(),
            aggregated_output: Vec::new(),
            tail_output: String::new(),
            child: None,
            stdin: None,
            scope_key: None,
            output_notify: Arc::new(Notify::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_can_spawn_initially() {
        let registry = ProcessRegistry::new();
        assert!(registry.can_spawn().await);
    }

    #[tokio::test]
    #[allow(clippy::cast_possible_truncation)]
    async fn registry_max_concurrent_respected() {
        let registry = ProcessRegistry::new();
        for i in 0..MAX_CONCURRENT {
            let session =
                ProcessSession::new_test(format!("s-{i}"), 1000 + i as u32, "sleep 60".into());
            registry.register(session).await;
        }
        assert!(!registry.can_spawn().await);
    }

    #[tokio::test]
    async fn registry_poll_drains_pending() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("poll-test".into(), 999, "echo".into());
        registry.register(session).await;

        registry.append_output("poll-test", b"hello world").await;

        let result = registry.poll("poll-test").await.unwrap();
        assert_eq!(result.new_output, "hello world");
        assert!(result.is_running);
        assert!(result.exit_code.is_none());

        // Second poll should be empty.
        let result2 = registry.poll("poll-test").await.unwrap();
        assert!(result2.new_output.is_empty());
    }

    #[tokio::test]
    async fn registry_mark_exited() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("exit-test".into(), 888, "true".into());
        registry.register(session).await;
        registry.mark_exited("exit-test", 0).await;

        let result = registry.poll("exit-test").await.unwrap();
        assert!(!result.is_running);
        assert_eq!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn registry_list_and_list_active() {
        let registry = ProcessRegistry::new();

        let s1 = ProcessSession::new_test("active".into(), 100, "sleep".into());
        let s2 = ProcessSession::new_test_exited("done".into(), 101, "true".into(), 0);
        registry.register(s1).await;
        registry.register(s2).await;

        assert_eq!(registry.list().await.len(), 2);
        assert_eq!(registry.list_active().await.len(), 1);
        assert_eq!(registry.list_active().await[0].session_id, "active");
    }

    #[tokio::test]
    async fn registry_read_log() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("log-test".into(), 777, "echo".into());
        registry.register(session).await;
        registry.append_output("log-test", b"line1\n").await;
        registry.append_output("log-test", b"line2\n").await;

        let log = registry.read_log("log-test").await.unwrap();
        assert_eq!(log, "line1\nline2\n");
    }

    #[tokio::test]
    async fn registry_output_cap_drops_oldest() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("cap-test".into(), 666, "cat".into());
        registry.register(session).await;

        // Write more than PENDING_OUTPUT_CAP.
        let chunk = vec![b'A'; PENDING_OUTPUT_CAP + 100];
        registry.append_output("cap-test", &chunk).await;

        let result = registry.poll("cap-test").await.unwrap();
        assert!(
            result.new_output.len() <= PENDING_OUTPUT_CAP,
            "pending output should be capped"
        );
    }

    // ── Phase 1: TTL Sweeper tests ────────────────────────────

    #[tokio::test]
    async fn sweep_expired_removes_old_sessions() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test_exited("old".into(), 1, "true".into(), 0);
        registry.register(session).await;
        // Zero TTL removes all exited sessions immediately.
        registry.sweep_expired(Duration::ZERO).await;
        assert!(registry.list().await.is_empty());
    }

    #[tokio::test]
    async fn sweep_expired_keeps_running_sessions() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("running".into(), 1, "sleep".into());
        registry.register(session).await;
        registry.sweep_expired(Duration::ZERO).await;
        assert_eq!(registry.list().await.len(), 1);
    }

    #[tokio::test]
    async fn sweep_expired_keeps_recently_exited() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test_exited("recent".into(), 1, "true".into(), 0);
        registry.register(session).await;
        // 1 hour TTL — recently exited session should be kept.
        registry.sweep_expired(Duration::from_secs(3600)).await;
        assert_eq!(registry.list().await.len(), 1);
    }

    // ── Phase 2: stdin Write tests ────────────────────────────

    #[tokio::test]
    async fn write_stdin_no_session() {
        let registry = ProcessRegistry::new();
        let result = registry.write_stdin("nonexistent", b"hello").await;
        assert!(result.is_err());
    }

    // ── Phase 3: Output Pagination tests ──────────────────────

    #[tokio::test]
    async fn read_log_paginated_offset() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("pg".into(), 1, "echo".into());
        registry.register(session).await;
        registry.append_output("pg", b"hello world").await;

        let (content, total) = registry.read_log_paginated("pg", 6, 1000).await.unwrap();
        assert_eq!(content, "world");
        assert_eq!(total, 11);
    }

    #[tokio::test]
    async fn read_log_paginated_limit() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("pg".into(), 1, "echo".into());
        registry.register(session).await;
        registry.append_output("pg", b"hello world").await;

        let (content, total) = registry.read_log_paginated("pg", 0, 5).await.unwrap();
        assert_eq!(content, "hello");
        assert_eq!(total, 11);
    }

    #[tokio::test]
    async fn read_log_paginated_offset_and_limit() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("pg".into(), 1, "echo".into());
        registry.register(session).await;
        registry.append_output("pg", b"hello world").await;

        let (content, total) = registry.read_log_paginated("pg", 2, 5).await.unwrap();
        assert_eq!(content, "llo w");
        assert_eq!(total, 11);
    }

    #[tokio::test]
    async fn read_log_paginated_offset_past_end() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("pg".into(), 1, "echo".into());
        registry.register(session).await;
        registry.append_output("pg", b"hello").await;

        let (content, total) = registry.read_log_paginated("pg", 100, 5).await.unwrap();
        assert!(content.is_empty());
        assert_eq!(total, 5);
    }

    // ── Phase 4: Agent Scoping tests ──────────────────────────

    #[tokio::test]
    async fn list_scoped_filters_correctly() {
        let registry = ProcessRegistry::new();
        let s1 = ProcessSession::new_test("a".into(), 1, "cmd".into())
            .with_scope_key(Some("agent-1".into()));
        let s2 = ProcessSession::new_test("b".into(), 2, "cmd".into())
            .with_scope_key(Some("agent-2".into()));
        let s3 = ProcessSession::new_test("c".into(), 3, "cmd".into());
        registry.register(s1).await;
        registry.register(s2).await;
        registry.register(s3).await;

        let all = registry.list_scoped(None).await;
        assert_eq!(all.len(), 3);

        let scoped = registry.list_scoped(Some("agent-1")).await;
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].session_id, "a");
    }

    #[tokio::test]
    async fn poll_scoped_rejects_wrong_scope() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("s".into(), 1, "cmd".into())
            .with_scope_key(Some("agent-1".into()));
        registry.register(session).await;
        registry.append_output("s", b"data").await;

        assert!(registry.poll_scoped("s", Some("agent-2")).await.is_none());
        // Correct scope works.
        assert!(registry.poll_scoped("s", Some("agent-1")).await.is_some());
    }

    #[tokio::test]
    async fn kill_scoped_rejects_wrong_scope() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("s".into(), 1, "cmd".into())
            .with_scope_key(Some("agent-1".into()));
        registry.register(session).await;

        assert!(registry.kill_scoped("s", Some("agent-2")).await.is_err());
    }

    #[tokio::test]
    async fn unscoped_methods_still_work() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("s".into(), 1, "cmd".into())
            .with_scope_key(Some("agent-1".into()));
        registry.register(session).await;
        registry.append_output("s", b"data").await;

        // Unscoped methods should work regardless of scope_key.
        assert!(registry.poll("s").await.is_some());
        assert!(registry.read_log("s").await.is_some());
        assert_eq!(registry.list().await.len(), 1);
    }

    // ── Phase 5: Long-poll tests ──────────────────────────────

    #[tokio::test]
    async fn poll_wait_returns_immediately_with_data() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("pw".into(), 1, "cmd".into());
        registry.register(session).await;
        registry.append_output("pw", b"data").await;

        let result = registry
            .poll_wait("pw", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result.new_output, "data");
    }

    #[tokio::test]
    async fn poll_wait_times_out_empty() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("pw".into(), 1, "cmd".into());
        registry.register(session).await;

        let start = Instant::now();
        let result = registry
            .poll_wait("pw", Duration::from_millis(100))
            .await
            .unwrap();
        assert!(result.new_output.is_empty());
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn poll_wait_wakes_on_append() {
        let registry = ProcessRegistry::new();
        let session = ProcessSession::new_test("pw".into(), 1, "cmd".into());
        registry.register(session).await;

        let reg_clone = registry.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            reg_clone.append_output("pw", b"wakeup").await;
        });

        let start = Instant::now();
        let result = registry
            .poll_wait("pw", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result.new_output, "wakeup");
        // Should wake up much sooner than the 5s timeout.
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
