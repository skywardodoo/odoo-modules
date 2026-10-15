from odoo import api, models
from odoo.http import request
from odoo.tools import config


class OAuthBase(models.AbstractModel):

    _name = 'skyward_mcp_oauth.base'
    _description = "MCP OAuth Helper"

    @api.model
    def get_base_url(self):
        configured = self.env['ir.config_parameter'].sudo().get_param(
            'skyward_mcp_oauth.base_url',
        )
        if configured:
            return configured.rstrip('/')
        return request.httprequest.host_url.rstrip('/')

    @api.model
    def audit_text(self, kind, client, scope=None):
        """Audit log wording, in the language of the company."""
        lang = self.env.company.partner_id.lang or 'en_US'
        env = self.with_context(lang=lang).env
        if kind == 'not_allowed':
            return env._("%(client)s: user not allowed", client=client)
        if kind == 'denied':
            return env._("%(client)s: user denied", client=client)
        label = (
            env._("read and write") if scope == 'write' else env._("read only")
        )
        return env._("%(client)s: %(scope)s", client=client, scope=label)

    @api.model
    def audit(self, event, status='ok', user=None, key=None, detail=None):
        """Record an OAuth event in the MCP audit log. Never stores secrets."""
        if not config.get('mcp_logging', True):
            return
        self.env['muk_mcp.log'].log(
            method='oauth/%s' % event,
            status=status,
            user_id=user.id if user else None,
            key_id=key.id if key else None,
            ip_address=request.httprequest.remote_addr if request else None,
            request_data=detail,
        )
