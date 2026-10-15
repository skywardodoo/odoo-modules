# MCP OAuth Access

Extends **MuK MCP Server** (`muk_mcp`) with per-user OAuth 2.1 sign-in and an
access group, so a connector shared by a whole organisation (for example a
Claude Team custom connector) needs no shared API key.

## What it adds

- OAuth discovery (RFC 9728 / RFC 8414), `authorize`, `token`, `revoke` and
  optional dynamic client registration (RFC 7591). Authorization code flow
  with mandatory PKCE (S256), rotating refresh tokens with a short grace window.
- Group **MCP Access**: only its members can sign in, hold a valid token or
  generate keys. Archived and portal users are always refused.
- Tokens are stored as regular `muk_mcp.key` records, so scope, rate limit,
  model whitelist (`muk_mcp_access`) and the audit log keep working. OAuth
  events (authorize, token, refresh, revoke, register) go to the audit log.
- Consent screen where the user can narrow a write request down to read only.

## Setup

1. Install the module and add the people allowed to use MCP to the group
   **MCP Access** (Settings > Users). Nobody is in it after install, so
   existing manual keys stop working until their owner is added.
2. Settings > MCP Server: review the token lifetimes, and the *Public Base
   URL* if Odoo sits behind a proxy that does not forward the host.
3. Settings > MCP > OAuth Clients: create a client for the connector.
   Redirect URI for Claude: `https://claude.ai/api/mcp/auth_callback`.
   Use *Generate Secret* (shown once) or tick *Public Client*.
   Alternatively enable *Dynamic Client Registration* and skip this step.
4. In the AI client add a custom connector with URL `https://<odoo>/mcp` and
   OAuth as authentication. Do **not** set an `Authorization` header: a header
   shared by the whole organisation is exactly what this module replaces.
5. Each person clicks Connect and signs in with their own Odoo user.

## Notes

- Writing is off unless the client has *Allow Write Scope* and the user agrees.
- Revoke a person's access by removing them from the group (tokens stop
  working immediately) or from OAuth Grants > Revoke.
- `muk_mcp`'s own test suite assumes users outside the group can use MCP;
  run it with *Require MCP Access Group* switched off.
