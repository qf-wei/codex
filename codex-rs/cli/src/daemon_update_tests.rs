#![cfg(test)]

use super::*;
use codex_tui::DaemonUpdateSource;
use pretty_assertions::assert_eq;
use std::os::unix::fs::PermissionsExt;

/// Egress-lockdown fork: every self-update path is refused before any updater
/// command (npm, pnpm, brew, curl installer, daemon handoff) is executed.
#[test]
fn every_update_action_is_refused_without_running_a_command() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let executable = dir.path().join("launching CLI");
    let receipt = dir.path().join("launching CLI.args");
    codex_utils_cargo_bin::write_executable(
        &executable,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\n",
    )?;
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(/*mode*/ 0o700))?;

    for action in [
        UpdateAction::Daemon(DaemonUpdateSource::PublicStable),
        UpdateAction::Daemon(DaemonUpdateSource::ThisCli),
        UpdateAction::NpmGlobalLatest,
        UpdateAction::BunGlobalLatest,
        UpdateAction::VitePlusGlobalLatest,
        UpdateAction::PnpmGlobalLatest,
        UpdateAction::BrewUpgrade,
        UpdateAction::StandaloneUnix,
        UpdateAction::StandaloneWindows,
    ] {
        let error = run_update_action(action, Some(&executable)).unwrap_err();
        assert!(
            error.to_string().contains("self-update is disabled"),
            "unexpected error for {action:?}: {error}"
        );
    }
    assert_eq!(receipt.exists(), false);
    Ok(())
}
