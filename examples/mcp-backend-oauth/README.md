# MCP backend OAuth (gateway as the OAuth client)

Hosted MCP servers such as Notion's (`https://mcp.notion.com/mcp`) only accept
OAuth 2.1 tokens obtained through a browser login with dynamic client
registration. With `backendAuth.oauthAuthorizationCode`, agentgateway holds that
login itself: you log in once, and clients connect to the gateway without ever
logging in to the upstream service.

### Log in once

```bash
cargo run -- oauth-login \
  --resource https://mcp.notion.com/mcp \
  --token-file examples/mcp-backend-oauth/notion-tokens.json
```

The command:

1. discovers the authorization server from the resource's protected-resource
   metadata (RFC 9728) and the server's metadata (RFC 8414);
2. registers a client (RFC 7591), unless you pass `--client-id`;
3. prints an authorization URL (authorization code + PKCE, with the RFC 8707
   `resource` parameter).

Open the URL in a browser and approve access. The browser returns to
`http://localhost:8976/callback`, where the command is listening. On a headless
server, open the URL on any machine; when the browser lands on the (unreachable)
localhost page, copy the full URL from the address bar and paste it into the
command. Alternatively forward the port: `ssh -L 8976:localhost:8976 server`.

The token file holds the client registration, access token and refresh token,
and is written with mode `0600`. Keep it private.

### Run the gateway

```bash
cargo run -- -f examples/mcp-backend-oauth/config.yaml
```

Then connect any MCP client to `http://localhost:3000/mcp`, for example
`npx @modelcontextprotocol/inspector`. The gateway attaches the access token to
upstream requests and refreshes it shortly before it expires, rewriting the
token file with any rotated refresh token.

### Notes

* One identity per target: every client behind the gateway acts as the account
  that logged in. Put inbound authentication (`jwtAuth`, `mcpAuthentication`) and
  `mcpAuthorization` in front of it.
* If the refresh token is revoked or expires, requests fail with a message to run
  `oauth-login` again. Re-running it replaces the file; the gateway picks up the
  new tokens without a restart.
* For a pre-registered client pass `--client-id` (and set
  `AGENTGATEWAY_OAUTH_CLIENT_SECRET` for a confidential client), and register
  `http://localhost:<port>/callback` as its redirect URI.
