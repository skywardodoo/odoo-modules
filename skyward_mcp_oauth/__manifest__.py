{
    'name': 'MCP OAuth Access',
    'summary': 'Per-user OAuth 2.1 login and an access group for the MuK MCP server',
    'description': '''
Extends MuK MCP Server so that connectors shared by a whole organisation
(for example a Claude Team custom connector) do not need a shared API key.
Every person signs in with their own Odoo user through a standard OAuth 2.1
authorization-code flow with PKCE, and only members of the "MCP Access" group
are let in.

* OAuth discovery, authorize, token, revoke and optional dynamic client
  registration endpoints.
* Access and refresh tokens are stored as regular MCP keys, so scope, rate
  limit, model whitelist and audit log keep working unchanged.
* Manual MCP keys are also refused for users outside the group, and only
  group members can generate keys.
    ''',
    'version': '18.0.1.0.0',
    'category': 'Tools/API',
    'license': 'LGPL-3',
    'author': 'Skyward',
    'depends': [
        'muk_mcp',
    ],
    'data': [
        'security/security.xml',
        'security/ir.model.access.csv',
        'views/templates.xml',
        'views/oauth_client.xml',
        'views/oauth_grant.xml',
        'views/res_config_settings.xml',
        'views/menu.xml',
    ],
    'installable': True,
    'application': False,
    'auto_install': False,
}
