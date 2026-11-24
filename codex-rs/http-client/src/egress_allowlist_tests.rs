use super::*;
use pretty_assertions::assert_eq;

fn allowed(url: &str) -> bool {
    is_allowed_egress_url_str(url)
}

#[test]
fn allows_loopback_over_plain_and_tls() {
    for url in [
        "http://localhost:11434/api/tags",
        "http://127.0.0.1:1234/v1/models",
        "ws://[::1]:8080/",
        "https://localhost/",
        "http://app.localhost/",
    ] {
        assert!(allowed(url), "{url} should be allowed");
    }
}

#[test]
fn allows_azure_and_aws_over_tls_only() {
    for url in [
        "https://myres.openai.azure.com/openai/v1/responses",
        "https://myres.cognitiveservices.azure.com/",
        "https://proj.services.ai.azure.com/",
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        "https://bedrock-runtime.us-west-2.amazonaws.com/",
        "https://bedrock-mantle.us-east-1.api.aws/openai/v1",
        "https://sts.amazonaws.com/",
        "wss://myres.openai.azure.com/openai/realtime",
    ] {
        assert!(allowed(url), "{url} should be allowed");
    }
    assert!(!allowed("http://myres.openai.azure.com/"));
    assert!(!allowed("http://bedrock-runtime.us-west-2.amazonaws.com/"));
}

#[test]
fn denies_openai_chatgpt_gov_and_third_parties() {
    for url in [
        "https://api.openai.com/v1/responses",
        "https://chatgpt.com/backend-api/codex/responses",
        "wss://chatgpt.com/backend-api/codex/responses",
        "https://auth.openai.com/oauth/token",
        "https://gov.chatgpt.com/backend-api/",
        "https://gov.api.openai.com/v1",
        "https://ab.chatgpt.com/otlp/v1/metrics",
        "https://o33249.ingest.us.sentry.io/",
        "https://api.github.com/repos/openai/codex/releases/latest",
        "https://registry.npmjs.org/@openai%2fcodex",
        "https://persistent.oaistatic.com/codex/pets/v1",
        "https://codex-portals.api.openai.com",
        "https://aiplatform.googleapis.com/v1",
        // Suffix tricks.
        "https://notazure.com/",
        "https://azure.com.evil.example/",
        "https://evilamazonaws.com/",
        "https://localhost.evil.example/",
        "http://10.0.0.1/",
        "file:///etc/passwd",
    ] {
        assert!(!allowed(url), "{url} should be denied");
    }
}

#[test]
fn host_checks_ignore_case_and_trailing_dot() {
    assert!(is_allowed_egress_host("Bedrock-Runtime.US-EAST-1.AmazonAWS.com."));
    assert!(is_allowed_egress_host("LOCALHOST"));
    assert!(!is_allowed_egress_host("chatgpt.com."));
}

#[test]
fn check_reports_blocked_host() {
    let url = Url::parse("https://api.openai.com/v1").expect("url");
    assert_eq!(
        check_egress_url(&url),
        Err(EgressDenied {
            host: "api.openai.com".to_string()
        })
    );
}

#[tokio::test]
async fn resolver_refuses_disallowed_names() {
    let name: Name = "chatgpt.com".parse().expect("name");
    let result = AllowlistResolver.resolve(name).await;
    assert!(result.is_err());

    let name: Name = "localhost".parse().expect("name");
    let addrs: Vec<SocketAddr> = AllowlistResolver
        .resolve(name)
        .await
        .expect("localhost resolves")
        .collect();
    assert!(addrs.iter().all(|addr| addr.ip().is_loopback()));
}
