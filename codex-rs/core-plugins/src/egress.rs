//! Egress-lockdown checks for plugin sources fetched by subprocesses (`git`, `npm`).
//!
//! These tools open their own network connections, so the HTTP client allowlist
//! does not see them. Every remote they are pointed at must match the same
//! compiled-in allowlist (loopback, Azure, AWS); local paths are always allowed.

use codex_http_client::is_allowed_egress_host;
use codex_http_client::is_allowed_egress_url_str;

/// Rejects git sources whose remote host is outside the egress allowlist.
pub(crate) fn ensure_git_source_allowed(source: &str) -> Result<(), String> {
    if git_source_allowed(source) {
        Ok(())
    } else {
        Err(format!(
            "git source `{source}` blocked by egress allowlist (only local paths, localhost, Azure and AWS are permitted)"
        ))
    }
}

/// Rejects npm package fetches unless an allowlisted registry is configured.
/// Without `--registry`, npm would contact the public registry.
pub(crate) fn ensure_npm_registry_allowed(registry: Option<&str>) -> Result<(), String> {
    match registry {
        Some(registry) if is_allowed_egress_url_str(registry) => Ok(()),
        Some(registry) => Err(format!(
            "npm registry `{registry}` blocked by egress allowlist (only localhost, Azure and AWS are permitted)"
        )),
        None => Err(
            "npm plugin sources require an explicit registry on localhost, Azure or AWS; the public npm registry is blocked by the egress allowlist"
                .to_string(),
        ),
    }
}

fn git_source_allowed(source: &str) -> bool {
    let source = source.trim();
    if let Some((scheme, rest)) = source.split_once("://") {
        return match scheme.to_ascii_lowercase().as_str() {
            "file" => true,
            "http" | "https" => is_allowed_egress_url_str(source),
            "ssh" | "git+ssh" | "ssh+git" => {
                let authority = rest.split('/').next().unwrap_or_default();
                let host = authority.rsplit('@').next().unwrap_or_default();
                let host = host.split(':').next().unwrap_or_default();
                is_allowed_egress_host(host)
            }
            _ => false,
        };
    }
    if let Some(host) = scp_like_host(source) {
        return is_allowed_egress_host(host);
    }
    // Plain filesystem path.
    true
}

/// Returns the host of scp-style git remotes such as `git@github.com:org/repo.git`.
fn scp_like_host(source: &str) -> Option<&str> {
    let colon = source.find(':')?;
    let before = &source[..colon];
    if before.is_empty() || before.contains('/') || before.contains('\\') {
        return None;
    }
    // Windows drive letters (`C:\repo`, `C:/repo`) are paths.
    if before.len() == 1 && before.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(before.rsplit('@').next().unwrap_or(before))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_sources() {
        for allowed in [
            "/home/me/plugins",
            "./plugins",
            "C:\\plugins",
            "file:///srv/plugins.git",
            "http://localhost:8080/plugins.git",
            "https://dev.azure.com/org/project/_git/plugins",
            "https://git-codecommit.us-east-1.amazonaws.com/v1/repos/plugins",
            "ssh://git@ssh.dev.azure.com/v3/org/project/plugins",
            "git@ssh.dev.azure.com:v3/org/project/plugins",
        ] {
            assert!(git_source_allowed(allowed), "{allowed} should be allowed");
        }
        for denied in [
            "https://github.com/openai/plugins.git",
            "git@github.com:openai/plugins.git",
            "ssh://git@github.com/openai/plugins.git",
            "git://github.com/openai/plugins.git",
            "http://dev.azure.com/org/project/_git/plugins",
        ] {
            assert!(!git_source_allowed(denied), "{denied} should be denied");
        }
    }

    #[test]
    fn npm_registries() {
        assert!(ensure_npm_registry_allowed(None).is_err());
        assert!(ensure_npm_registry_allowed(Some("https://registry.npmjs.org")).is_err());
        assert!(ensure_npm_registry_allowed(Some("http://localhost:4873")).is_ok());
        assert!(
            ensure_npm_registry_allowed(Some(
                "https://pkgs.dev.azure.com/org/_packaging/feed/npm/registry/"
            ))
            .is_ok()
        );
    }
}
