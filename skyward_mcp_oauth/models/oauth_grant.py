import secrets
from datetime import timedelta

from odoo import api, fields, models
from odoo.tools import SQL

from .oauth_client import hash_secret
from .oauth_code import OAuthError

SCOPE_LABELS = {'read': 'mcp:read', 'write': 'mcp:write'}


class OAuthGrant(models.Model):

    _name = 'skyward_mcp_oauth.grant'
    _description = "MCP OAuth Grant"
    _order = 'id desc'

    # ----------------------------------------------------------
    # Fields
    # ----------------------------------------------------------

    client_id = fields.Many2one(
        comodel_name='skyward_mcp_oauth.client',
        string="Client",
        required=True,
        ondelete='cascade',
        index=True,
    )

    user_id = fields.Many2one(
        comodel_name='res.users',
        string="User",
        required=True,
        ondelete='cascade',
        index=True,
    )

    key_id = fields.Many2one(
        comodel_name='muk_mcp.key',
        string="MCP Key",
        ondelete='cascade',
        index=True,
    )

    scope = fields.Selection(
        selection=[('read', "Read Only"), ('write', "Read & Write")],
        required=True,
        default='read',
    )

    resource = fields.Char(
        string="Audience",
        required=True,
        help="The MCP endpoint these tokens are valid for.",
    )

    refresh_hash = fields.Char(index=True)

    previous_refresh_hash = fields.Char(index=True)

    access_expires = fields.Datetime(string="Access Token Expires")

    refresh_expires = fields.Datetime(string="Refresh Token Expires")

    revoked = fields.Boolean(string="Revoked", default=False)

    last_refresh = fields.Datetime(string="Last Refresh")

    _sql_constraints = [
        ('refresh_hash_unique', 'unique(refresh_hash)',
         "Refresh token hashes must be unique."),
        ('key_unique', 'unique(key_id)',
         "A key can belong to a single grant."),
    ]

    # ----------------------------------------------------------
    # Helper
    # ----------------------------------------------------------

    @api.model
    def _grace(self):
        seconds = int(self.env['ir.config_parameter'].sudo().get_param(
            'skyward_mcp_oauth.refresh_grace_seconds', 5,
        ))
        return timedelta(seconds=max(seconds, 0))

    @api.model
    def _ttl(self):
        param = self.env['ir.config_parameter'].sudo()
        minutes = int(param.get_param('skyward_mcp_oauth.access_token_minutes', 15))
        days = int(param.get_param('skyward_mcp_oauth.refresh_token_days', 30))
        return timedelta(minutes=max(minutes, 1)), timedelta(days=max(days, 1))

    def _new_tokens(self):
        """Rotate access and refresh tokens on this grant, return the raw pair."""
        self.ensure_one()
        access_ttl, refresh_ttl = self._ttl()
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        key_model = self.env['muk_mcp.key'].sudo()
        key_values = {
            'key_hash': key_model._hash_key(access),
            'key_prefix': access[:8],
            'active': True,
        }
        if self.key_id:
            self.key_id.sudo().write(key_values)
        else:
            rate = int(self.env['ir.config_parameter'].sudo().get_param(
                'muk_mcp.rate_limit_requests', 60,
            ))
            self.key_id = key_model.create({
                **key_values,
                'name': "OAuth: %s" % self.client_id.name,
                'user_id': self.user_id.id,
                'scope': self.scope,
                'rate_limit': rate,
            })
        now = fields.Datetime.now()
        self.write({
            'previous_refresh_hash': self.refresh_hash,
            'refresh_hash': hash_secret(refresh),
            'access_expires': now + access_ttl,
            'refresh_expires': now + refresh_ttl,
            'last_refresh': now,
        })
        return {
            'access_token': access,
            'token_type': 'Bearer',
            'expires_in': int(access_ttl.total_seconds()),
            'refresh_token': refresh,
            'scope': SCOPE_LABELS[self.scope],
        }

    def _revoke(self):
        self.sudo().write({'revoked': True})
        self.key_id.sudo().write({'active': False})

    # ----------------------------------------------------------
    # Functions
    # ----------------------------------------------------------

    @api.model
    def _issue(self, client, user, scope, resource):
        grant = self.sudo().create({
            'client_id': client.id,
            'user_id': user.id,
            'scope': scope,
            'resource': resource,
        })
        return grant, grant._new_tokens()

    @api.model
    def _refresh(self, raw, client):
        invalid = OAuthError('invalid_grant', "The refresh token is invalid.")
        if not raw:
            raise invalid
        digest = hash_secret(raw)
        self.env.cr.execute(SQL(
            """
            SELECT id, refresh_hash = %s FROM %s
            WHERE refresh_hash = %s OR previous_refresh_hash = %s
            LIMIT 1 FOR UPDATE
            """,
            digest, SQL.identifier(self._table), digest, digest,
        ))
        row = self.env.cr.fetchone()
        if not row:
            raise invalid
        grant = self.sudo().browse(row[0])
        if grant.client_id != client or grant.revoked:
            raise invalid
        if not row[1]:
            # A rotated refresh token came back. Right after a rotation it is
            # a client retrying a response it never received; later on it
            # means the token leaked.
            now = fields.Datetime.now()
            if not (grant.last_refresh and now - grant.last_refresh <= self._grace()):
                grant._revoke()
                raise invalid
        if grant.refresh_expires < fields.Datetime.now():
            raise invalid
        if not self.env['muk_mcp.key']._user_allowed(grant.user_id):
            grant._revoke()
            raise invalid
        return grant, grant._new_tokens()

    @api.model
    def _revoke_by_token(self, raw):
        if not raw:
            return
        digest = hash_secret(raw)
        key = self.env['muk_mcp.key'].sudo()._hash_key(raw)
        grants = self.sudo().search(['|', '|',
            ('refresh_hash', '=', digest),
            ('previous_refresh_hash', '=', digest),
            ('key_id.key_hash', '=', key),
        ])
        for grant in grants:
            grant._revoke()

    def action_revoke(self):
        self._revoke()

    @api.autovacuum
    def _gc_grants(self):
        now = fields.Datetime.now()
        stale = self.sudo().search([
            '|', ('revoked', '=', True), ('refresh_expires', '<', now),
        ])
        stale.filtered(lambda g: not g.revoked)._revoke()
        limit = now - timedelta(days=30)
        stale.filtered(
            lambda g: g.write_date and g.write_date < limit
        ).unlink()
