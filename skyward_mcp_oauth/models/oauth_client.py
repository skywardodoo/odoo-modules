import hashlib
import hmac
import secrets
from datetime import timedelta
from urllib.parse import urlsplit

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError

LOOPBACK_HOSTS = ('localhost', '127.0.0.1', '[::1]', '::1')


def hash_secret(value):
    return hashlib.sha256(value.encode()).hexdigest()


class OAuthClient(models.Model):

    _name = 'skyward_mcp_oauth.client'
    _description = "MCP OAuth Client"
    _order = 'name'

    # ----------------------------------------------------------
    # Fields
    # ----------------------------------------------------------

    name = fields.Char(
        string="Name",
        required=True,
        help="Shown to the user on the consent screen.",
    )

    client_id = fields.Char(
        string="Client ID",
        required=True,
        readonly=True,
        copy=False,
        index=True,
        default=lambda self: secrets.token_urlsafe(16),
    )

    secret_hash = fields.Char(
        string="Secret Hash",
        readonly=True,
        copy=False,
    )

    is_public = fields.Boolean(
        string="Public Client",
        default=False,
        help="A public client has no secret and relies on PKCE only.",
    )

    redirect_uris = fields.Text(
        string="Redirect URIs",
        required=True,
        help="One URI per line. Matched exactly.",
    )

    allow_write = fields.Boolean(
        string="Allow Write Scope",
        default=False,
        help="Let this client obtain tokens with the read & write scope. "
             "Read only otherwise.",
    )

    dynamic = fields.Boolean(
        string="Dynamically Registered",
        readonly=True,
    )

    active = fields.Boolean(
        string="Active",
        default=True,
    )

    grant_ids = fields.One2many(
        comodel_name='skyward_mcp_oauth.grant',
        inverse_name='client_id',
        string="Grants",
    )

    _sql_constraints = [
        ('client_id_unique', 'unique(client_id)', "The client ID must be unique."),
    ]

    # ----------------------------------------------------------
    # Constraints
    # ----------------------------------------------------------

    @api.constrains('redirect_uris')
    def _check_redirect_uris(self):
        for client in self:
            uris = client._get_redirect_uris()
            if not uris:
                raise ValidationError(_("At least one redirect URI is required."))
            for uri in uris:
                if not self._is_valid_redirect_uri(uri):
                    raise ValidationError(_(
                        "Invalid redirect URI %s: it must be https (http is "
                        "only allowed for loopback addresses) and carry no "
                        "fragment.", uri,
                    ))

    # ----------------------------------------------------------
    # Helper
    # ----------------------------------------------------------

    @api.model
    def _is_valid_redirect_uri(self, uri):
        try:
            parts = urlsplit(uri)
            host = parts.hostname
        except ValueError:
            return False
        if not host or parts.fragment or parts.username or parts.password:
            return False
        if parts.scheme == 'https':
            return True
        return parts.scheme == 'http' and host in LOOPBACK_HOSTS

    def _get_redirect_uris(self):
        self.ensure_one()
        return [
            line.strip()
            for line in (self.redirect_uris or '').splitlines()
            if line.strip()
        ]

    def _check_redirect_uri(self, uri):
        self.ensure_one()
        return bool(uri) and uri in self._get_redirect_uris()

    def _verify_secret(self, secret):
        self.ensure_one()
        if self.is_public:
            return True
        if not (secret and self.secret_hash):
            return False
        return hmac.compare_digest(self.secret_hash, hash_secret(secret))

    def _new_secret(self):
        self.ensure_one()
        raw = secrets.token_urlsafe(32)
        self.sudo().secret_hash = hash_secret(raw)
        return raw

    @api.autovacuum
    def _gc_dynamic_clients(self):
        """Drop self-registered clients nobody ever signed in with."""
        limit = fields.Datetime.now() - timedelta(days=1)
        stale = self.sudo().with_context(active_test=False).search([
            ('dynamic', '=', True), ('create_date', '<', limit),
        ])
        stale.filtered(lambda client: not client.grant_ids).unlink()

    # ----------------------------------------------------------
    # Actions
    # ----------------------------------------------------------

    def action_generate_secret(self):
        self.ensure_one()
        if self.is_public:
            raise ValidationError(_("A public client has no secret."))
        raw = self._new_secret()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _("New client secret"),
                'message': _(
                    "Copy it now, it is shown only once: %s", raw,
                ),
                'type': 'warning',
                'sticky': True,
            },
        }
