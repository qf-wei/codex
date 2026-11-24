//! Hard-coded outbound destination allowlist for this fork.
//!
//! Every application-owned network call (HTTP, WebSocket, OTEL export, git
//! remotes, telemetry) must pass [`is_allowed_egress_url`] or
//! [`is_allowed_egress_host`]. The list is compiled in and cannot be widened by
//! configuration, so ChatGPT, OpenAI (including FedRAMP/gov hosts), GitHub,
//! Sentry, Statsig, npm and every other third party are unreachable.
//!
//! Allowed:
//! - loopback (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`) over any of
//!   `http`, `https`, `ws`, `wss`;
//! - Azure (`*.azure.com`, `*.azure.net`, `*.azure-api.net`,
//!   `*.microsoftonline.com`) over `https`/`wss` only;
//! - AWS (`*.amazonaws.com`, `*.api.aws`) over `https`/`wss` only.
//!
//! Shell commands executed by the agent are governed by the sandbox, not by
//! this list.

use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;

use reqwest::Url;
use reqwest::dns::Addrs;
use reqwest::dns::Name;
use reqwest::dns::Resolve;
use reqwest::dns::Resolving;

/// Remote domain suffixes that may be contacted over TLS. A host matches when
/// it equals the suffix or ends with `.` + suffix.
pub const ALLOWED_REMOTE_DOMAIN_SUFFIXES: &[&str] = &[
    // Azure OpenAI / Azure AI services / APIM / Entra ID.
    "azure.com",
    "azure.net",
    "azure-api.net",
    "microsoftonline.com",
    // AWS (Bedrock runtime, Bedrock Mantle, STS, SSO, ...).
    "amazonaws.com",
    "api.aws",
];

/// Returns true when `host` (a DNS name or IP literal, without port) is a
/// loopback destination.
pub fn is_loopback_host(host: &str) -> bool {
    let host = normalize_host(host);
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    let ip_literal = host.trim_start_matches('[').trim_end_matches(']');
    ip_literal
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

/// Returns true when `host` matches one of [`ALLOWED_REMOTE_DOMAIN_SUFFIXES`].
pub fn is_allowed_remote_host(host: &str) -> bool {
    let host = normalize_host(host);
    ALLOWED_REMOTE_DOMAIN_SUFFIXES.iter().any(|suffix| {
        host == *suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// Returns true when a bare host name may be contacted at all (loopback or an
/// allowed remote suffix). Use [`is_allowed_egress_url`] when a URL is
/// available so the scheme is checked too.
pub fn is_allowed_egress_host(host: &str) -> bool {
    is_loopback_host(host) || is_allowed_remote_host(host)
}

/// Returns true when the fork permits a request to `url`.
pub fn is_allowed_egress_url(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let scheme = url.scheme();
    if is_loopback_host(host) {
        return matches!(scheme, "http" | "https" | "ws" | "wss");
    }
    matches!(scheme, "https" | "wss") && is_allowed_remote_host(host)
}

/// Same as [`is_allowed_egress_url`] for an unparsed URL string. Unparseable
/// input is denied.
pub fn is_allowed_egress_url_str(url: &str) -> bool {
    Url::parse(url).is_ok_and(|url| is_allowed_egress_url(&url))
}

/// Returns an error describing the blocked destination when `url` is denied.
pub fn check_egress_url(url: &Url) -> Result<(), EgressDenied> {
    if is_allowed_egress_url(url) {
        Ok(())
    } else {
        Err(EgressDenied {
            host: url.host_str().unwrap_or_default().to_string(),
        })
    }
}

/// A destination rejected by the compiled-in egress allowlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressDenied {
    pub host: String,
}

impl fmt::Display for EgressDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "outbound connection to `{}` blocked by egress allowlist (only localhost, Azure and AWS are permitted)",
            self.host
        )
    }
}

impl Error for EgressDenied {}

fn normalize_host(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// DNS resolver installed on every reqwest client built by this crate. It
/// refuses to resolve names outside the allowlist, which also covers redirect
/// hops and any direct `reqwest` use that skips the URL checks.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AllowlistResolver;

impl Resolve for AllowlistResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            if !is_allowed_egress_host(&host) {
                return Err(Box::new(EgressDenied { host }) as Box<dyn Error + Send + Sync>);
            }
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)?
                .collect();
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
#[path = "egress_allowlist_tests.rs"]
mod tests;
