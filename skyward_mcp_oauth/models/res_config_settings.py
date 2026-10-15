from odoo import api, fields, models


class ResConfigSettings(models.TransientModel):

    _inherit = 'res.config.settings'

    # ----------------------------------------------------------
    # Fields
    # ----------------------------------------------------------

    mcp_oauth_require_group = fields.Boolean(
        string="Require MCP Access Group",
        config_parameter='skyward_mcp_oauth.require_group',
        default=True,
        help="Only members of the MCP Access group can use MCP, with an "
             "OAuth token or a manual key.",
    )

    mcp_oauth_dynamic_registration = fields.Boolean(
        string="Allow Dynamic Client Registration",
        config_parameter='skyward_mcp_oauth.allow_dynamic_registration',
        default=False,
        help="Let MCP clients register themselves (RFC 7591). Users still "
             "have to sign in and approve each client.",
    )

    mcp_oauth_access_token_minutes = fields.Integer(
        string="Access Token Lifetime (minutes)",
        config_parameter='skyward_mcp_oauth.access_token_minutes',
        default=15,
    )

    mcp_oauth_refresh_token_days = fields.Integer(
        string="Refresh Token Lifetime (days)",
        config_parameter='skyward_mcp_oauth.refresh_token_days',
        default=30,
    )

    mcp_oauth_refresh_grace_seconds = fields.Integer(
        string="Refresh Grace Window (seconds)",
        config_parameter='skyward_mcp_oauth.refresh_grace_seconds',
        default=5,
        help="A refresh token reused within this window right after a "
             "rotation is treated as a retry instead of a theft.",
    )

    mcp_oauth_base_url = fields.Char(
        string="Public Base URL",
        config_parameter='skyward_mcp_oauth.base_url',
        help="Override the URL advertised in the OAuth metadata. Leave empty "
             "to use the one of the incoming request.",
    )
