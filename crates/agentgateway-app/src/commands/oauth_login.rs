use agentgateway::http::auth::oauth::authorization_code::{LoginOptions, login};

use crate::OAuthLoginArgs;

pub(crate) fn execute(args: OAuthLoginArgs) -> anyhow::Result<()> {
	let rt = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?;
	let result = rt.block_on(login(LoginOptions {
		resource: args.resource,
		token_file: args.token_file,
		issuer: args.issuer,
		client_id: args.client_id,
		client_secret: args
			.client_secret
			.or_else(|| std::env::var("AGENTGATEWAY_OAUTH_CLIENT_SECRET").ok()),
		scopes: args.scopes,
		port: args.port,
	}));
	// Don't wait on the blocking stdin read when the browser redirect won.
	rt.shutdown_background();
	result
}
