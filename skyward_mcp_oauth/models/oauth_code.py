import base64
import hashlib
import hmac
import re
import secrets
from datetime import timedelta

from odoo import api, fields, models
from odoo.tools import SQL

from .oauth_client import hash_secret

CODE_TTL_SECONDS = 300
VERIFIER_RE = re.compile(r'^[A-Za-z0-9\-._~]{43,128}$')


class OAuthError(Exception):

    def __init__(self, error, description=None, status=400):
        super().__init__(error)
        self.error = error
        self.description = description
        self.status = status


def pkce_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()


class OAuthCode(models.Model):

    _name = 'skyward_mcp_oauth.code'
    _description = "MCP OAuth Authorization Code"

    # ----------------------------------------------------------
    # Fields
    # ----------------------------------------------------------

    code_hash = fields.Char(required=True, index=True)

    client_id = fields.Many2one(
        comodel_name='skyward_mcp_oauth.client',
        required=True,
        ondelete='cascade',
    )

    user_id = fields.Many2one(
        comodel_name='res.users',
        required=True,
        ondelete='cascade',
    )

    redirect_uri = fields.Char(required=True)

    code_challenge = fields.Char(required=True)

    scope = fields.Char(required=True)

    resource = fields.Char(required=True)

    expires_at = fields.Datetime(required=True)

    used = fields.Boolean(default=False)

    grant_id = fields.Many2one(
        comodel_name='skyward_mcp_oauth.grant',
        ondelete='set null',
    )

    _sql_constraints = [
        ('code_hash_unique', 'unique(code_hash)',
         "Authorization code hashes must be unique."),
    ]

    # ----------------------------------------------------------
    # Functions
    # ----------------------------------------------------------

    @api.model
    def _issue(self, client, user, redirect_uri, code_challenge, scope, resource):
        raw = secrets.token_urlsafe(32)
        self.sudo().create({
            'code_hash': hash_secret(raw),
            'client_id': client.id,
            'user_id': user.id,
            'redirect_uri': redirect_uri,
            'code_challenge': code_challenge,
            'scope': scope,
            'resource': resource,
            'expires_at': fields.Datetime.now() + timedelta(
                seconds=CODE_TTL_SECONDS,
            ),
        })
        return raw

    @api.model
    def _consume(self, raw, client, redirect_uri, verifier):
        """Validate and burn an authorization code, return the code record."""
        invalid = OAuthError('invalid_grant', "The authorization code is invalid.")
        if not raw:
            raise invalid
        self.env.cr.execute(SQL(
            "SELECT id FROM %s WHERE code_hash = %s FOR UPDATE",
            SQL.identifier(self._table),
            hash_secret(raw),
        ))
        row = self.env.cr.fetchone()
        if not row:
            raise invalid
        code = self.sudo().browse(row[0])
        if code.used:
            # A replayed code means it leaked: kill what it produced.
            if code.grant_id:
                code.grant_id._revoke()
            raise invalid
        if (
            code.client_id != client
            or code.expires_at < fields.Datetime.now()
            or code.redirect_uri != redirect_uri
        ):
            raise invalid
        if not (verifier and VERIFIER_RE.match(verifier)):
            raise OAuthError('invalid_grant', "Missing or malformed code_verifier.")
        if not hmac.compare_digest(
            pkce_challenge(verifier), code.code_challenge,
        ):
            raise OAuthError('invalid_grant', "PKCE verification failed.")
        return code

    @api.autovacuum
    def _gc_codes(self):
        limit = fields.Datetime.now() - timedelta(days=1)
        self.sudo().search([('expires_at', '<', limit)]).unlink()
