use super::process_registry::ProcessRegistry;
use super::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Tool for managing background processes (list, poll, kill, log, write).
/// Follows the SubagentsTool pattern for process lifecycle management.
pub struct ProcessTool {
    registry: Arc<ProcessRegistry>,
}

impl ProcessTool {
    pub fn new(registry: Arc<ProcessRegistry>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Tool for ProcessTool {
    fn name(&self) -> &str {
        "process"
    }

    fn description(&self) -> &str {
        "Manage background processes: list running processes, poll for output, kill a process, read the full log, or write to stdin"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "poll", "kill", "log", "write"],
                    "description": "Action to perform: list all sessions, poll for new output, kill a process, read full log, or write to stdin"
                },
                "session_id": {
                    "type": "string",
                    "description": "Session ID (required for poll, kill, log, write)"
                },
                "input": {
                    "type": "string",
                    "description": "Input data to write to process stdin (required for write)"
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Byte offset for paginated log reads"
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Maximum bytes for paginated log reads"
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 120,
                    "description": "Long-poll timeout in seconds (poll only, 0 = no wait)"
                },
                "scope_key": {
                    "type": "string",
                    "description": "Agent scope key for session isolation"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'action' parameter"))?;

        let session_id = args.get("session_id").and_then(|v| v.as_str());
        let scope_key = args.get("scope_key").and_then(|v| v.as_str());

        match action {
            "list" => {
                let sessions = self.registry.list_scoped(scope_key).await;
                let list: Vec<serde_json::Value> = sessions
                    .iter()
                    .map(|s| {
                        json!({
                            "session_id": s.session_id,
                            "pid": s.pid,
                            "command": s.command,
                            "is_running": s.is_running,
                            "exit_code": s.exit_code,
                            "elapsed_secs": s.started_at.elapsed().as_secs(),
                            "scope_key": s.scope_key,
                        })
                    })
                    .collect();
                Ok(ToolResult {
                    success: true,
                    output: serde_json::to_string_pretty(&list)
                        .unwrap_or_else(|_| "[]".to_string()),
                    error: None,
                })
            }

            "poll" => {
                let id =
                    session_id.ok_or_else(|| anyhow::anyhow!("'session_id' required for poll"))?;
                let timeout_secs = args
                    .get("timeout_seconds")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let result = if timeout_secs > 0 {
                    self.registry
                        .poll_wait(id, Duration::from_secs(timeout_secs.min(120)))
                        .await
                } else {
                    self.registry.poll_scoped(id, scope_key).await
                };

                match result {
                    Some(result) => {
                        let output = json!({
                            "session_id": id,
                            "new_output": result.new_output,
                            "is_running": result.is_running,
                            "exit_code": result.exit_code,
                        });
                        Ok(ToolResult {
                            success: true,
                            output: serde_json::to_string_pretty(&output).unwrap_or_default(),
                            error: None,
                        })
                    }
                    None => Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("No session with id '{id}'")),
                    }),
                }
            }

            "kill" => {
                let id =
                    session_id.ok_or_else(|| anyhow::anyhow!("'session_id' required for kill"))?;
                match self.registry.kill_scoped(id, scope_key).await {
                    Ok(()) => Ok(ToolResult {
                        success: true,
                        output: format!("Process session '{id}' killed"),
                        error: None,
                    }),
                    Err(e) => Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    }),
                }
            }

            "log" => {
                let id =
                    session_id.ok_or_else(|| anyhow::anyhow!("'session_id' required for log"))?;
                let offset = args.get("offset").and_then(|v| v.as_u64());
                let limit = args.get("limit").and_then(|v| v.as_u64());

                if offset.is_some() || limit.is_some() {
                    // Paginated read.
                    #[allow(clippy::cast_possible_truncation)]
                    let off = offset.unwrap_or(0) as usize;
                    #[allow(clippy::cast_possible_truncation)]
                    let lim = limit.unwrap_or(200 * 1024) as usize;
                    match self.registry.read_log_paginated(id, off, lim).await {
                        Some((content, total_bytes)) => {
                            let output = json!({
                                "session_id": id,
                                "content": content,
                                "offset": off,
                                "total_bytes": total_bytes,
                            });
                            Ok(ToolResult {
                                success: true,
                                output: serde_json::to_string_pretty(&output).unwrap_or_default(),
                                error: None,
                            })
                        }
                        None => Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(format!("No session with id '{id}'")),
                        }),
                    }
                } else {
                    // Full log with scope filtering.
                    match self.registry.read_log_scoped(id, scope_key).await {
                        Some(log) => Ok(ToolResult {
                            success: true,
                            output: log,
                            error: None,
                        }),
                        None => Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(format!("No session with id '{id}'")),
                        }),
                    }
                }
            }

            "write" => {
                let id =
                    session_id.ok_or_else(|| anyhow::anyhow!("'session_id' required for write"))?;
                let input = args
                    .get("input")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("'input' required for write"))?;
                match self.registry.write_stdin(id, input.as_bytes()).await {
                    Ok(()) => Ok(ToolResult {
                        success: true,
                        output: format!("Wrote {} bytes to session '{id}'", input.len()),
                        error: None,
                    }),
                    Err(e) => Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    }),
                }
            }

            other => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Unknown action '{other}'. Valid actions: list, poll, kill, log, write"
                )),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::process_registry::ProcessSession;

    fn test_registry() -> Arc<ProcessRegistry> {
        Arc::new(ProcessRegistry::new())
    }

    #[tokio::test]
    async fn process_tool_name() {
        let tool = ProcessTool::new(test_registry());
        assert_eq!(tool.name(), "process");
    }

    #[tokio::test]
    async fn process_tool_list_empty() {
        let tool = ProcessTool::new(test_registry());
        let result = tool.execute(json!({"action": "list"})).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains("[]"));
    }

    #[tokio::test]
    async fn process_tool_list_with_sessions() {
        let registry = test_registry();
        let session =
            ProcessSession::new_test_exited("test-session".into(), 12345, "echo hello".into(), 0);
        registry.register(session).await;

        let tool = ProcessTool::new(registry);
        let result = tool.execute(json!({"action": "list"})).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains("test-session"));
    }

    #[tokio::test]
    async fn process_tool_poll_nonexistent() {
        let tool = ProcessTool::new(test_registry());
        let result = tool
            .execute(json!({"action": "poll", "session_id": "nope"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("nope"));
    }

    #[tokio::test]
    async fn process_tool_poll_with_output() {
        let registry = test_registry();
        let session = ProcessSession::new_test("poll-sess".into(), 999, "echo".into());
        registry.register(session).await;
        registry.append_output("poll-sess", b"output data").await;

        let tool = ProcessTool::new(registry);
        let result = tool
            .execute(json!({"action": "poll", "session_id": "poll-sess"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("output data"));
    }

    #[tokio::test]
    async fn process_tool_unknown_action() {
        let tool = ProcessTool::new(test_registry());
        let result = tool.execute(json!({"action": "invalid"})).await.unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Unknown action"));
    }

    #[tokio::test]
    async fn process_tool_missing_session_id() {
        let tool = ProcessTool::new(test_registry());
        let result = tool.execute(json!({"action": "poll"})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn process_tool_write_missing_input() {
        let registry = test_registry();
        let session = ProcessSession::new_test("write-test".into(), 1, "cmd".into());
        registry.register(session).await;

        let tool = ProcessTool::new(registry);
        let result = tool
            .execute(json!({"action": "write", "session_id": "write-test"}))
            .await;
        assert!(result.is_err());
    }
}
