//! Backend auth where the gateway is the OAuth client of an upstream service, such as a
//! hosted MCP server that only accepts tokens from a browser login.
//!
//! `agentgateway oauth-login` performs the one-time discovery (RFC 9728, RFC 8414),
//! dynamic client registration (RFC 7591) and authorization-code + PKCE login, and writes
//! a token file. At runtime the gateway reads that file, attaches the access token to
//! backend requests and refreshes it before it expires, rewriting the file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use ::http::{Method, StatusCode};
use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::trace;

use crate::http::auth::{AuthorizationLocation, BackendAuthError, insert_local_auth};
use crate::http::filters::BackendRequestTimeout;
use crate::http::oauth::{
	authorization_server_metadata_url, encode_client_secret_basic, format_token_endpoint_error_body,
	openid_configuration_metadata_url,
};
use crate::http::{Body, Request};
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
use crate::{apply, schema};

/// Refresh the access token this many seconds before it expires.
const REFRESH_SKEW_SECS: u64 = 60;
const TOKEN_RESPONSE_LIMIT: usize = 64 * 1024;
const TOKEN_ENDPOINT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[apply(schema!)]
pub struct OAuthAuthorizationCodeAuth {
	/// Token file written by `agentgateway oauth-login`. It holds the client registration and
	/// tokens, and is rewritten when the access token is refreshed. Keep it private.
	token_file: PathBuf,
	/// Where to place the access token in the backend request. Defaults to the
	/// Authorization header with a "Bearer " prefix.
	#[serde(default)]
	authorization_location: AuthorizationLocation,
	#[serde(skip)]
	#[cfg_attr(feature = "schema", schemars(skip))]
	state: Arc<Mutex<Option<StoredTokens>>>,
}

impl OAuthAuthorizationCodeAuth {
	pub(crate) fn validate_load(&self) -> Result<(), String> {
		if matches!(
			self.authorization_location,
			AuthorizationLocation::Expression(_)
		) {
			return Err("expression auth location is only supported for credential extraction".into());
		}
		Ok(())
	}

	async fn access_token(&self, client: &PolicyClient) -> Result<String, BackendAuthError> {
		// Held across the refresh so concurrent requests share one refresh.
		let mut state = self.state.lock().await;
		let now = unix_now();
		if let Some(tokens) = state.as_ref().filter(|t| t.is_fresh(now)) {
			return Ok(tokens.access_token.clone());
		}
		// Re-read the file: a new `oauth-login` may have replaced it.
		let mut tokens = read_token_file(&self.token_file)
			.await
			.map_err(BackendAuthError::local)?;
		if !tokens.is_fresh(now) {
			let req = tokens
				.refresh_request()
				.and_then(|r| r.into_http())
				.map_err(BackendAuthError::local)?;
			let resp = refresh_via(client, req)
				.await
				.map_err(BackendAuthError::credential_provider)?;
			tokens.update(resp, now);
			write_token_file(&self.token_file, &tokens)
				.await
				.map_err(BackendAuthError::local)?;
			trace!("refreshed oauth authorization-code access token");
		}
		let token = tokens.access_token.clone();
		*state = Some(tokens);
		Ok(token)
	}
}

pub(in crate::http::auth) async fn apply(
	inputs: &Arc<crate::ProxyInputs>,
	auth: &OAuthAuthorizationCodeAuth,
	req: &mut Request,
) -> Result<bool, ProxyError> {
	let client = PolicyClient::new(inputs.clone()).with_parent(req);
	let token = auth.access_token(&client).await?;
	insert_local_auth(&auth.authorization_location, req, &token)?;
	Ok(true)
}

async fn refresh_via(
	client: &PolicyClient,
	mut req: ::http::Request<Body>,
) -> anyhow::Result<TokenResponse> {
	req
		.extensions_mut()
		.insert(BackendRequestTimeout(TOKEN_ENDPOINT_TIMEOUT));
	let resp = client
		.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Oidc)
		.simple_call(req)
		.await
		.context("token refresh request failed")?;
	let status = resp.status();
	let body = crate::http::read_body_with_limit(resp.into_body(), TOKEN_RESPONSE_LIMIT).await?;
	parse_token_response(status, &body)
}

/// Contents of the token file.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredTokens {
	token_endpoint: String,
	client_id: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	client_secret: Option<String>,
	/// RFC 7591 `token_endpoint_auth_method` returned at registration.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	token_endpoint_auth_method: Option<String>,
	/// RFC 8707 resource indicator sent on token requests.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	resource: Option<String>,
	access_token: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	refresh_token: Option<String>,
	/// Unix seconds. Unset when the token endpoint gave no `expires_in`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	expires_at: Option<u64>,
}

// Keep tokens out of logs and config dumps.
impl std::fmt::Debug for StoredTokens {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("StoredTokens")
			.field("token_endpoint", &self.token_endpoint)
			.field("client_id", &self.client_id)
			.field("expires_at", &self.expires_at)
			.finish_non_exhaustive()
	}
}

impl StoredTokens {
	fn is_fresh(&self, now: u64) -> bool {
		// ponytail: without expires_in the token is used until replaced; refreshing on a backend
		// 401 would cover servers that omit it.
		self
			.expires_at
			.is_none_or(|exp| now + REFRESH_SKEW_SECS < exp)
	}

	fn refresh_request(&self) -> anyhow::Result<TokenRequest> {
		let refresh_token = self.refresh_token.clone().ok_or_else(|| {
			anyhow!(
				"access token expired and no refresh token is stored; run `agentgateway oauth-login` again"
			)
		})?;
		let mut form = vec![
			("grant_type", "refresh_token".to_string()),
			("refresh_token", refresh_token),
		];
		if let Some(resource) = &self.resource {
			form.push(("resource", resource.clone()));
		}
		Ok(self.token_request(form))
	}

	fn token_request(&self, mut form: Vec<(&'static str, String)>) -> TokenRequest {
		let mut basic = None;
		match (
			&self.client_secret,
			self.token_endpoint_auth_method.as_deref(),
		) {
			(Some(secret), Some("client_secret_basic")) => {
				basic = Some(encode_client_secret_basic(
					&self.client_id,
					&SecretString::from(secret.clone()),
				));
			},
			(Some(secret), _) => {
				form.push(("client_id", self.client_id.clone()));
				form.push(("client_secret", secret.clone()));
			},
			(None, _) => form.push(("client_id", self.client_id.clone())),
		}
		TokenRequest {
			endpoint: self.token_endpoint.clone(),
			form,
			basic,
		}
	}

	fn update(&mut self, resp: TokenResponse, now: u64) {
		self.access_token = resp.access_token;
		// Servers that do not rotate refresh tokens omit it; keep the old one.
		if resp.refresh_token.is_some() {
			self.refresh_token = resp.refresh_token;
		}
		self.expires_at = resp.expires_in.map(|s| now + s);
	}
}

struct TokenRequest {
	endpoint: String,
	form: Vec<(&'static str, String)>,
	basic: Option<String>,
}

impl TokenRequest {
	fn body(&self) -> anyhow::Result<String> {
		Ok(serde_urlencoded::to_string(&self.form)?)
	}

	fn into_http(self) -> anyhow::Result<::http::Request<Body>> {
		let mut builder = ::http::Request::builder()
			.method(Method::POST)
			.uri(&self.endpoint)
			.header(CONTENT_TYPE, "application/x-www-form-urlencoded")
			.header(ACCEPT, "application/json");
		if let Some(basic) = &self.basic {
			builder = builder.header(AUTHORIZATION, format!("Basic {basic}"));
		}
		Ok(builder.body(Body::from(self.body()?))?)
	}

	async fn send(self, http: &reqwest::Client) -> anyhow::Result<TokenResponse> {
		let mut req = http
			.post(&self.endpoint)
			.header(CONTENT_TYPE, "application/x-www-form-urlencoded")
			.header(ACCEPT, "application/json")
			.body(self.body()?);
		if let Some(basic) = &self.basic {
			req = req.header(AUTHORIZATION, format!("Basic {basic}"));
		}
		let resp = req.send().await.context("token request failed")?;
		let status = resp.status();
		let body = resp.bytes().await?;
		parse_token_response(status, &body)
	}
}

#[derive(Deserialize)]
struct TokenResponse {
	access_token: String,
	#[serde(default)]
	token_type: Option<String>,
	#[serde(default)]
	refresh_token: Option<String>,
	#[serde(default)]
	expires_in: Option<u64>,
}

fn parse_token_response(status: StatusCode, body: &[u8]) -> anyhow::Result<TokenResponse> {
	if !status.is_success() {
		bail!(
			"token endpoint returned {status}: {}",
			format_token_endpoint_error_body(body, 256)
		);
	}
	let resp: TokenResponse =
		serde_json::from_slice(body).context("token endpoint response decode failed")?;
	if resp.access_token.is_empty() {
		bail!("token endpoint returned an empty access_token");
	}
	if let Some(token_type) = &resp.token_type
		&& !token_type.eq_ignore_ascii_case("Bearer")
	{
		bail!("token endpoint returned unsupported token_type {token_type}");
	}
	Ok(resp)
}

async fn read_token_file(path: &Path) -> anyhow::Result<StoredTokens> {
	let contents = tokio::fs::read(path).await.with_context(|| {
		format!(
			"reading oauth token file {}; run `agentgateway oauth-login` first",
			path.display()
		)
	})?;
	serde_json::from_slice(&contents)
		.with_context(|| format!("parsing oauth token file {}", path.display()))
}

// ponytail: plaintext JSON readable only by the owner (0600), like gh's hosts.yml; encrypt at
// rest with a key from a file or env var if the host is shared.
async fn write_token_file(path: &Path, tokens: &StoredTokens) -> anyhow::Result<()> {
	let tmp = path.with_extension("tmp");
	let _ = tokio::fs::remove_file(&tmp).await;
	let mut opts = tokio::fs::OpenOptions::new();
	opts.write(true).create_new(true);
	#[cfg(unix)]
	opts.mode(0o600);
	let mut file = opts
		.open(&tmp)
		.await
		.with_context(|| format!("writing oauth token file {}", tmp.display()))?;
	file.write_all(&serde_json::to_vec_pretty(tokens)?).await?;
	file.sync_all().await?;
	tokio::fs::rename(&tmp, path)
		.await
		.with_context(|| format!("replacing oauth token file {}", path.display()))
}

fn unix_now() -> u64 {
	super::super::unix_timestamp_now().unwrap_or_default()
}

fn random_token(bytes: usize) -> String {
	let mut random = vec![0; bytes];
	crate::crypto::rand::fill(&mut random).expect("secure RNG must not fail");
	URL_SAFE_NO_PAD.encode(random)
}

// ----- One-time login (`agentgateway oauth-login`) -----

pub struct LoginOptions {
	/// URL of the protected resource, such as `https://mcp.notion.com/mcp`.
	pub resource: String,
	pub token_file: PathBuf,
	/// Authorization server issuer; discovered from the resource when unset.
	pub issuer: Option<String>,
	/// Pre-registered client; dynamic client registration is used when unset.
	pub client_id: Option<String>,
	pub client_secret: Option<String>,
	pub scopes: Vec<String>,
	/// Loopback port for the redirect URI.
	pub port: u16,
}

#[derive(Deserialize)]
struct ProtectedResourceMetadata {
	#[serde(default)]
	authorization_servers: Vec<String>,
}

#[derive(Deserialize)]
struct AuthorizationServerMetadata {
	authorization_endpoint: String,
	token_endpoint: String,
	#[serde(default)]
	registration_endpoint: Option<String>,
	#[serde(default)]
	code_challenge_methods_supported: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RegistrationResponse {
	client_id: String,
	#[serde(default)]
	client_secret: Option<String>,
	#[serde(default)]
	token_endpoint_auth_method: Option<String>,
}

pub async fn login(opts: LoginOptions) -> anyhow::Result<()> {
	let http = reqwest::Client::new();
	let issuer = match opts.issuer.clone() {
		Some(issuer) => issuer,
		None => discover_issuer(&http, &opts.resource).await?,
	};
	let meta = discover_authorization_server(&http, &issuer).await?;
	if let Some(methods) = &meta.code_challenge_methods_supported
		&& !methods.iter().any(|m| m == "S256")
	{
		bail!("authorization server {issuer} does not support PKCE S256");
	}

	let redirect_uri = format!("http://localhost:{}/callback", opts.port);
	let registration = match opts.client_id.clone() {
		Some(client_id) => RegistrationResponse {
			client_id,
			client_secret: opts.client_secret.clone(),
			token_endpoint_auth_method: None,
		},
		None => register_client(&http, &meta, &redirect_uri).await?,
	};
	let mut tokens = StoredTokens {
		token_endpoint: meta.token_endpoint.clone(),
		client_id: registration.client_id,
		client_secret: registration.client_secret,
		token_endpoint_auth_method: registration.token_endpoint_auth_method,
		resource: Some(opts.resource.clone()),
		access_token: String::new(),
		refresh_token: None,
		expires_at: None,
	};

	let verifier = random_token(32);
	let state = random_token(16);
	let auth_url = authorization_url(&meta, &tokens, &opts, &redirect_uri, &verifier, &state)?;
	eprintln!(
		"Open this URL in a browser and approve access:\n\n  {auth_url}\n\n\
		 Waiting for the browser to return to {redirect_uri} ...\n\
		 On a headless host, paste the full URL the browser was sent to (it may show a connection error) and press Enter:"
	);
	let callback = wait_for_callback(opts.port).await?;
	let code = callback_code(&callback, &state)?;

	let req = tokens.token_request(vec![
		("grant_type", "authorization_code".to_string()),
		("code", code),
		("redirect_uri", redirect_uri),
		("code_verifier", verifier),
		("resource", opts.resource.clone()),
	]);
	let resp = req.send(&http).await?;
	tokens.update(resp, unix_now());
	write_token_file(&opts.token_file, &tokens).await?;
	eprintln!(
		"Login complete. Tokens saved to {}",
		opts.token_file.display()
	);
	Ok(())
}

fn authorization_url(
	meta: &AuthorizationServerMetadata,
	tokens: &StoredTokens,
	opts: &LoginOptions,
	redirect_uri: &str,
	verifier: &str,
	state: &str,
) -> anyhow::Result<url::Url> {
	let challenge = URL_SAFE_NO_PAD.encode(crate::crypto::digest::sha256(verifier.as_bytes()));
	let mut url = url::Url::parse(&meta.authorization_endpoint).with_context(|| {
		format!(
			"invalid authorization_endpoint {}",
			meta.authorization_endpoint
		)
	})?;
	{
		let mut q = url.query_pairs_mut();
		q.append_pair("response_type", "code")
			.append_pair("client_id", &tokens.client_id)
			.append_pair("redirect_uri", redirect_uri)
			.append_pair("code_challenge", &challenge)
			.append_pair("code_challenge_method", "S256")
			.append_pair("state", state)
			.append_pair("resource", &opts.resource);
		if !opts.scopes.is_empty() {
			q.append_pair("scope", &opts.scopes.join(" "));
		}
	}
	Ok(url)
}

/// Candidate RFC 9728 metadata URLs: path-inserted first, then the origin root.
fn protected_resource_metadata_urls(resource: &str) -> anyhow::Result<Vec<String>> {
	let url =
		url::Url::parse(resource).with_context(|| format!("invalid resource URL {resource}"))?;
	let origin = url.origin().ascii_serialization();
	let root = format!("{origin}/.well-known/oauth-protected-resource");
	let path = url.path().trim_end_matches('/');
	Ok(if path.is_empty() {
		vec![root]
	} else {
		vec![format!("{root}{path}"), root]
	})
}

async fn discover_issuer(http: &reqwest::Client, resource: &str) -> anyhow::Result<String> {
	for url in protected_resource_metadata_urls(resource)? {
		if let Some(meta) = get_json::<ProtectedResourceMetadata>(http, &url).await?
			&& let Some(issuer) = meta.authorization_servers.into_iter().next()
		{
			return Ok(issuer);
		}
	}
	// MCP 2025-03-26 fallback: the authorization server is the resource's origin.
	let url = url::Url::parse(resource)?;
	Ok(url.origin().ascii_serialization())
}

async fn discover_authorization_server(
	http: &reqwest::Client,
	issuer: &str,
) -> anyhow::Result<AuthorizationServerMetadata> {
	for url in [
		authorization_server_metadata_url(issuer),
		openid_configuration_metadata_url(issuer),
	] {
		if let Some(meta) = get_json(http, &url).await? {
			return Ok(meta);
		}
	}
	bail!("no OAuth authorization server metadata found for {issuer}; pass --issuer")
}

/// GETs JSON, returning `None` for a non-success status.
async fn get_json<T: serde::de::DeserializeOwned>(
	http: &reqwest::Client,
	url: &str,
) -> anyhow::Result<Option<T>> {
	let resp = http
		.get(url)
		.header(ACCEPT, "application/json")
		.send()
		.await
		.with_context(|| format!("fetching {url}"))?;
	if !resp.status().is_success() {
		return Ok(None);
	}
	let body = resp.bytes().await?;
	Ok(Some(
		serde_json::from_slice(&body).with_context(|| format!("parsing {url}"))?,
	))
}

async fn register_client(
	http: &reqwest::Client,
	meta: &AuthorizationServerMetadata,
	redirect_uri: &str,
) -> anyhow::Result<RegistrationResponse> {
	let Some(endpoint) = &meta.registration_endpoint else {
		bail!("authorization server does not support dynamic client registration; pass --client-id");
	};
	let body = serde_json::json!({
		"client_name": "agentgateway",
		"redirect_uris": [redirect_uri],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "none",
	});
	let resp = http
		.post(endpoint)
		.header(CONTENT_TYPE, "application/json")
		.header(ACCEPT, "application/json")
		.body(body.to_string())
		.send()
		.await
		.context("client registration request failed")?;
	let status = resp.status();
	let body = resp.bytes().await?;
	if !status.is_success() {
		bail!(
			"client registration returned {status}: {}",
			format_token_endpoint_error_body(&body, 256)
		);
	}
	serde_json::from_slice(&body).context("client registration response decode failed")
}

/// Waits for the authorization redirect, either on the loopback listener or pasted on stdin.
/// Returns the full redirect URL.
async fn wait_for_callback(port: u16) -> anyhow::Result<String> {
	let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
		.await
		.with_context(|| format!("listening on 127.0.0.1:{port}; pass a free --port"))?;
	let from_listener = async {
		loop {
			let (mut stream, _) = listener.accept().await?;
			let mut buf = vec![0; 8192];
			let n = stream.read(&mut buf).await?;
			let head = String::from_utf8_lossy(&buf[..n]);
			// Request line: "GET /callback?code=... HTTP/1.1"
			let Some(target) = head.split_whitespace().nth(1) else {
				continue;
			};
			if !target.starts_with("/callback") {
				let _ = stream
					.write_all(b"HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n")
					.await;
				continue;
			}
			let _ = stream
				.write_all(
					b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nLogin received; you can close this window.\n",
				)
				.await;
			return anyhow::Ok(format!("http://localhost:{port}{target}"));
		}
	};
	let from_stdin = async {
		let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
		while let Some(line) = lines.next_line().await? {
			if !line.trim().is_empty() {
				return anyhow::Ok(line.trim().to_string());
			}
		}
		// No terminal (stdin closed): only the loopback listener can complete the login.
		std::future::pending().await
	};
	tokio::select! {
		url = from_listener => url,
		url = from_stdin => url,
	}
}

fn callback_code(callback: &str, expected_state: &str) -> anyhow::Result<String> {
	let url =
		url::Url::parse(callback).with_context(|| format!("invalid redirect URL {callback}"))?;
	let param = |name: &str| {
		url
			.query_pairs()
			.find(|(k, _)| k == name)
			.map(|(_, v)| v.into_owned())
	};
	if let Some(error) = param("error") {
		bail!(
			"authorization failed: {error} {}",
			param("error_description").unwrap_or_default()
		);
	}
	if param("state").as_deref() != Some(expected_state) {
		bail!("redirect state does not match this login; start again");
	}
	param("code").ok_or_else(|| anyhow!("redirect URL has no code parameter"))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn tokens() -> StoredTokens {
		StoredTokens {
			token_endpoint: "https://as.example.com/token".into(),
			client_id: "client".into(),
			client_secret: None,
			token_endpoint_auth_method: None,
			resource: Some("https://mcp.example.com/mcp".into()),
			access_token: "old".into(),
			refresh_token: Some("refresh-1".into()),
			expires_at: Some(1_000),
		}
	}

	#[test]
	fn freshness_uses_skew() {
		let t = tokens();
		assert!(t.is_fresh(1_000 - REFRESH_SKEW_SECS - 1));
		assert!(!t.is_fresh(1_000 - REFRESH_SKEW_SECS));
		assert!(
			StoredTokens {
				expires_at: None,
				..tokens()
			}
			.is_fresh(u64::MAX / 2)
		);
	}

	#[test]
	fn refresh_request_public_client() {
		let req = tokens().refresh_request().unwrap();
		assert_eq!(
			req.body().unwrap(),
			"grant_type=refresh_token&refresh_token=refresh-1&resource=https%3A%2F%2Fmcp.example.com%2Fmcp&client_id=client"
		);
		assert!(req.basic.is_none());
	}

	#[test]
	fn refresh_request_client_secret_basic() {
		let t = StoredTokens {
			client_secret: Some("s3cret".into()),
			token_endpoint_auth_method: Some("client_secret_basic".into()),
			..tokens()
		};
		let req = t.refresh_request().unwrap();
		assert!(!req.body().unwrap().contains("s3cret"));
		assert!(req.basic.is_some());
	}

	#[test]
	fn refresh_requires_refresh_token() {
		let t = StoredTokens {
			refresh_token: None,
			..tokens()
		};
		assert!(t.refresh_request().is_err());
	}

	#[test]
	fn update_keeps_refresh_token_when_not_rotated() {
		let mut t = tokens();
		t.update(
			TokenResponse {
				access_token: "new".into(),
				token_type: Some("Bearer".into()),
				refresh_token: None,
				expires_in: Some(3600),
			},
			2_000,
		);
		assert_eq!(t.access_token, "new");
		assert_eq!(t.refresh_token.as_deref(), Some("refresh-1"));
		assert_eq!(t.expires_at, Some(5_600));
	}

	#[test]
	fn token_response_validation() {
		assert!(
			parse_token_response(StatusCode::BAD_REQUEST, br#"{"error":"invalid_grant"}"#).is_err()
		);
		assert!(
			parse_token_response(
				StatusCode::OK,
				br#"{"access_token":"a","token_type":"mac"}"#
			)
			.is_err()
		);
		assert!(parse_token_response(StatusCode::OK, br#"{"access_token":""}"#).is_err());
		let ok = parse_token_response(
			StatusCode::OK,
			br#"{"access_token":"a","token_type":"bearer","refresh_token":"r","expires_in":60}"#,
		)
		.unwrap();
		assert_eq!(ok.refresh_token.as_deref(), Some("r"));
	}

	#[test]
	fn protected_resource_metadata_candidates() {
		assert_eq!(
			protected_resource_metadata_urls("https://mcp.example.com/mcp").unwrap(),
			[
				"https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
				"https://mcp.example.com/.well-known/oauth-protected-resource",
			]
		);
		assert_eq!(
			protected_resource_metadata_urls("https://mcp.example.com/").unwrap(),
			["https://mcp.example.com/.well-known/oauth-protected-resource"]
		);
	}

	#[test]
	fn callback_checks_state_and_errors() {
		let ok = "http://localhost:1/callback?code=abc&state=xyz";
		assert_eq!(callback_code(ok, "xyz").unwrap(), "abc");
		assert!(callback_code(ok, "other").is_err());
		assert!(
			callback_code(
				"http://localhost:1/callback?error=access_denied&state=xyz",
				"xyz"
			)
			.is_err()
		);
	}

	#[tokio::test]
	async fn refreshes_expired_token_once_and_persists_rotation() {
		use wiremock::matchers::{body_string_contains, method, path};
		use wiremock::{Mock, MockServer, ResponseTemplate};

		let mock = MockServer::start().await;
		Mock::given(method("POST"))
			.and(path("/token"))
			.and(body_string_contains("grant_type=refresh_token"))
			.and(body_string_contains("refresh_token=refresh-1"))
			.respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
				"access_token": "fresh",
				"token_type": "Bearer",
				"refresh_token": "refresh-2",
				"expires_in": 3600,
			})))
			.expect(1)
			.mount(&mock)
			.await;

		let dir = tempfile::tempdir().unwrap();
		let token_file = dir.path().join("tokens.json");
		let stale = StoredTokens {
			token_endpoint: format!("{}/token", mock.uri()),
			..tokens()
		};
		write_token_file(&token_file, &stale).await.unwrap();

		let auth: OAuthAuthorizationCodeAuth =
			serde_json::from_value(serde_json::json!({ "tokenFile": token_file })).unwrap();
		let client = PolicyClient::new(
			crate::test_helpers::proxymock::setup_proxy_test("{}")
				.unwrap()
				.inputs(),
		);
		assert_eq!(auth.access_token(&client).await.unwrap(), "fresh");
		// Served from memory; the mock's expect(1) fails the test on a second refresh.
		assert_eq!(auth.access_token(&client).await.unwrap(), "fresh");

		let saved = read_token_file(&token_file).await.unwrap();
		assert_eq!(saved.access_token, "fresh");
		assert_eq!(saved.refresh_token.as_deref(), Some("refresh-2"));
	}

	#[tokio::test]
	async fn token_file_round_trip_is_private() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("tokens.json");
		write_token_file(&path, &tokens()).await.unwrap();
		write_token_file(&path, &tokens()).await.unwrap();
		let read = read_token_file(&path).await.unwrap();
		assert_eq!(read.refresh_token.as_deref(), Some("refresh-1"));
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let mode = std::fs::metadata(&path).unwrap().permissions().mode();
			assert_eq!(mode & 0o777, 0o600);
		}
	}
}
