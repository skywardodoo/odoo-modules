from odoo import api, fields, models
from odoo.http import request
from odoo.tools.misc import str2bool

GROUP = 'skyward_mcp_oauth.group_mcp_user'


class MCPKey(models.Model):

    _inherit = 'muk_mcp.key'

    # ----------------------------------------------------------
    # Helper
    # ----------------------------------------------------------

    @api.model
    def _require_group(self):
        return str2bool(
            self.env['ir.config_parameter'].sudo().get_param(
                'skyward_mcp_oauth.require_group', 'True',
            ),
            default=True,
        )

    @api.model
    def _user_allowed(self, user):
        """Whether ``user`` may use MCP at all, whatever token they hold."""
        user = user.sudo()
        if not user.active or user.share:
            return False
        return not self._require_group() or user.has_group(GROUP)

    # ----------------------------------------------------------
    # Functions
    # ----------------------------------------------------------

    @api.model
    def authenticate(self, token):
        key = super().authenticate(token)
        if not key:
            return key
        if not self._user_allowed(key.user_id):
            return None
        grant = self.env['skyward_mcp_oauth.grant'].sudo().search(
            [('key_id', '=', key.id)], limit=1,
        )
        if grant and (
            grant.revoked
            or grant.access_expires < fields.Datetime.now()
            or not self._audience_ok(grant)
        ):
            return None
        return key

    @api.model
    def _audience_ok(self, grant):
        """Tokens only work on the endpoint that issued them.

        A copy of the database served from another host (a staging build, for
        instance) therefore cannot be used with tokens minted elsewhere.
        """
        if not (request and request.httprequest):
            return True
        base = self.env['skyward_mcp_oauth.base'].get_base_url()
        return grant.resource == '%s/mcp' % base
