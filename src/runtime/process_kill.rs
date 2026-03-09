use std::time::Duration;
use tokio::process::Child;

/// Kill a process and its entire process group with graceful shutdown.
///
/// 1. Send SIGTERM to the process group (all children spawned under setsid).
/// 2. Wait up to `grace` for natural exit.
/// 3. If still alive, send SIGKILL to the process group.
///
/// On non-Unix platforms, falls back to `child.kill()`.
pub async fn kill_process_tree(child: &mut Child, grace: Duration) {
    #[cfg(unix)]
    {
        if let Some(raw_pid) = child.id() {
            let pid = raw_pid as i32;
            // SIGTERM to process group (-pid targets the entire group)
            // Safety: libc::kill is a standard POSIX call.
            unsafe {
                libc::kill(-pid, libc::SIGTERM);
            }

            // Wait for graceful exit within the grace period.
            if tokio::time::timeout(grace, child.wait()).await.is_ok() {
                return;
            }

            // Still alive — SIGKILL the entire process group.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            // Reap to avoid zombie.
            let _ = child.wait().await;
            return;
        }
        // No PID available (already exited?) — try direct kill as fallback.
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    #[cfg(not(unix))]
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_process_tree_kills_children() {
        use tokio::process::Command;

        // Spawn a shell that starts background children.
        // setsid is applied via pre_exec in NativeRuntime, but for this unit test
        // we apply it inline so the test is self-contained.
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("sleep 60 & sleep 60 & wait");
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());

        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }

        let mut child = cmd.kill_on_drop(true).spawn().expect("spawn failed");
        let pid = child.id().expect("no pid") as i32;

        // Give children time to start.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify the process group exists.
        let pg_alive = unsafe { libc::kill(-pid, 0) } == 0;
        assert!(pg_alive, "process group should be alive before kill");

        kill_process_tree(&mut child, Duration::from_secs(2)).await;

        // Small delay for OS cleanup.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Process group should be gone.
        let pg_dead = unsafe { libc::kill(-pid, 0) } != 0;
        assert!(pg_dead, "process group should be dead after kill");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn graceful_shutdown_within_grace_period() {
        use tokio::process::Command;

        // Process that traps SIGTERM and exits cleanly.
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("trap 'exit 0' TERM; sleep 60 & wait");
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());

        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }

        let mut child = cmd.kill_on_drop(true).spawn().expect("spawn failed");

        // Give time for trap to be set up.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let start = std::time::Instant::now();
        kill_process_tree(&mut child, Duration::from_secs(5)).await;
        let elapsed = start.elapsed();

        // Should have exited via SIGTERM well within the 5s grace period.
        assert!(
            elapsed < Duration::from_secs(4),
            "process should exit gracefully via SIGTERM, took {elapsed:?}"
        );
    }
}
