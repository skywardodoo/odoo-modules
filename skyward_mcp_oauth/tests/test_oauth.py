import base64
import hashlib
import re
import secrets
from datetime import timedelta
from urllib.parse import parse_qs, urlencode, urlsplit

from odoo import fields
from odoo.exceptions import AccessError
from odoo.tests import tagged
from odoo.tests.common import new_test_user

from odoo.addons.muk_mcp.tests.common import MCPHttpCase

REDIRECT = 'https://client.example.com/callback'
GROUP = 'skyward_mcp_oauth.group_mcp_user'


def make_pkce():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge


@tagged('post_install', '-at_install')
class TestMCPOAuth(MCPHttpCase):

    # ----------------------------------------------------------
    # Setup
    # ----------------------------------------------------------

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.member = new_test_user(
            cls.env, login='oauth_member',
            groups='base.group_user,%s' % GROUP,
        )
        cls.outsider = new_test_user(
            cls.env, login='oauth_outsider', groups='base.group_user',
        )
        cls.client = cls.env['skyward_mcp_oauth.client'].create({
            'name': 'Test Client',
            'is_public': True,
            'redirect_uris': REDIRECT,
        })
        cls.env['ir.config_parameter'].sudo().set_param(
            'skyward_mcp_oauth.require_group', 'True',
        )

    # ----------------------------------------------------------
    # Helper
    # ----------------------------------------------------------

    def authorize_params(self, challenge, **extra):
        params = {
            'response_type': 'code',
            'client_id': self.client.client_id,
            'redirect_uri': REDIRECT,
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'state': 'xyz',
        }
        params.update(extra)
        return {k: v for k, v in params.items() if v is not None}

    def get(self, path, params=None, **kwargs):
        if params:
            path = '%s?%s' % (path, urlencode(params))
        return self.url_open(path, **kwargs)

    def login(self, user):
        self.authenticate(user.login, user.login)

    def approve(self, user, challenge, decision='approve', **extra):
        """Walk the browser flow, return the redirect Location."""
        self.login(user)
        params = self.authorize_params(challenge, **extra)
        page = self.get('/mcp/oauth/authorize', params)
        self.assertEqual(page.status_code, 200)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        response = self.url_open(
            '/mcp/oauth/authorize',
            data={**params, 'csrf_token': csrf, 'decision': decision},
            allow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        return response.headers['Location']

    def get_code(self, user, challenge):
        location = self.approve(user, challenge)
        query = parse_qs(urlsplit(location).query)
        self.assertEqual(query['state'], ['xyz'])
        return query['code'][0]

    def token_request(self, **data):
        data.setdefault('client_id', self.client.client_id)
        return self.url_open('/mcp/oauth/token', data=data)

    def exchange(self, code, verifier, **extra):
        return self.token_request(
            grant_type='authorization_code', code=code,
            redirect_uri=REDIRECT, code_verifier=verifier, **extra,
        )

    def full_flow(self, user=None):
        verifier, challenge = make_pkce()
        code = self.get_code(user or self.member, challenge)
        response = self.exchange(code, verifier)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def ping_status(self, token):
        return self.mcp_post(self.mcp_ping(), token=token).status_code

    # ----------------------------------------------------------
    # Tests: Discovery
    # ----------------------------------------------------------

    def test_discovery_documents(self):
        base = self.base_url()
        resource = self.url_open('/.well-known/oauth-protected-resource').json()
        self.assertEqual(resource['resource'], base + '/mcp')
        self.assertEqual(resource['authorization_servers'], [base])
        meta = self.url_open('/.well-known/oauth-authorization-server').json()
        self.assertEqual(meta['token_endpoint'], base + '/mcp/oauth/token')
        self.assertEqual(meta['code_challenge_methods_supported'], ['S256'])
        self.assertNotIn('registration_endpoint', meta)

    def test_unauthorized_advertises_resource_metadata(self):
        response = self.mcp_post(self.mcp_ping(), token=False)
        self.assertEqual(response.status_code, 401)
        challenge = response.headers['WWW-Authenticate']
        self.assertIn('Bearer', challenge)
        self.assertIn('/.well-known/oauth-protected-resource', challenge)

    # ----------------------------------------------------------
    # Tests: Authorization flow
    # ----------------------------------------------------------

    def test_full_flow_issues_working_read_token(self):
        tokens = self.full_flow()
        self.assertEqual(tokens['token_type'], 'Bearer')
        self.assertEqual(tokens['scope'], 'mcp:read')
        self.assertEqual(self.ping_status(tokens['access_token']), 200)
        key = self.env['muk_mcp.key'].authenticate(tokens['access_token'])
        self.assertEqual(key.user_id, self.member)
        self.assertEqual(key.scope, 'read')

    def test_anonymous_authorize_redirects_to_login(self):
        _verifier, challenge = make_pkce()
        response = self.get(
            '/mcp/oauth/authorize',
            self.authorize_params(challenge), allow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn('/web/login', response.headers['Location'])

    def test_user_outside_group_is_refused(self):
        _verifier, challenge = make_pkce()
        self.login(self.outsider)
        response = self.get(
            '/mcp/oauth/authorize',
            self.authorize_params(challenge), allow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        query = parse_qs(urlsplit(response.headers['Location']).query)
        self.assertEqual(query['error'], ['access_denied'])
        self.assertNotIn('code', query)

    def test_deny_returns_access_denied(self):
        _verifier, challenge = make_pkce()
        location = self.approve(self.member, challenge, decision='deny')
        query = parse_qs(urlsplit(location).query)
        self.assertEqual(query['error'], ['access_denied'])

    def test_unknown_redirect_uri_is_never_redirected_to(self):
        _verifier, challenge = make_pkce()
        self.login(self.member)
        response = self.get(
            '/mcp/oauth/authorize',
            self.authorize_params(
                challenge, redirect_uri='https://evil.example.com/cb',
            ),
            allow_redirects=False,
        )
        self.assertEqual(response.status_code, 400)

    def test_pkce_is_mandatory(self):
        self.login(self.member)
        params = self.authorize_params('x', code_challenge_method='plain')
        response = self.get(
            '/mcp/oauth/authorize', params, allow_redirects=False,
        )
        query = parse_qs(urlsplit(response.headers['Location']).query)
        self.assertEqual(query['error'], ['invalid_request'])

    def test_write_scope_needs_client_permission(self):
        verifier, challenge = make_pkce()
        location = self.approve(
            self.member, challenge, scope='mcp:write',
        )
        code = parse_qs(urlsplit(location).query)['code'][0]
        tokens = self.exchange(code, verifier).json()
        self.assertEqual(tokens['scope'], 'mcp:read')
        self.client.allow_write = True
        verifier, challenge = make_pkce()
        location = self.approve(
            self.member, challenge, scope='mcp:write', grant_write='1',
        )
        code = parse_qs(urlsplit(location).query)['code'][0]
        tokens = self.exchange(code, verifier).json()
        self.assertEqual(tokens['scope'], 'mcp:write')
        # Narrowing at the consent screen yields a read-only token.
        verifier, challenge = make_pkce()
        location = self.approve(
            self.member, challenge, scope='mcp:write',
        )
        code = parse_qs(urlsplit(location).query)['code'][0]
        tokens = self.exchange(code, verifier).json()
        self.assertEqual(tokens['scope'], 'mcp:read')

    # ----------------------------------------------------------
    # Tests: Token endpoint
    # ----------------------------------------------------------

    def test_wrong_verifier_is_rejected(self):
        _verifier, challenge = make_pkce()
        code = self.get_code(self.member, challenge)
        other, _challenge = make_pkce()
        response = self.exchange(code, other)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_code_replay_revokes_the_grant(self):
        verifier, challenge = make_pkce()
        code = self.get_code(self.member, challenge)
        tokens = self.exchange(code, verifier).json()
        self.assertEqual(self.ping_status(tokens['access_token']), 200)
        replay = self.exchange(code, verifier)
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(self.ping_status(tokens['access_token']), 401)

    def test_redirect_uri_must_match_at_exchange(self):
        verifier, challenge = make_pkce()
        code = self.get_code(self.member, challenge)
        response = self.token_request(
            grant_type='authorization_code', code=code,
            redirect_uri='https://client.example.com/other',
            code_verifier=verifier,
        )
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_confidential_client_needs_its_secret(self):
        client = self.env['skyward_mcp_oauth.client'].create({
            'name': 'Confidential',
            'redirect_uris': REDIRECT,
        })
        secret = client._new_secret()
        response = self.url_open('/mcp/oauth/token', data={
            'grant_type': 'refresh_token', 'refresh_token': 'x',
            'client_id': client.client_id, 'client_secret': 'wrong',
        })
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['error'], 'invalid_client')
        response = self.url_open('/mcp/oauth/token', data={
            'grant_type': 'refresh_token', 'refresh_token': 'x',
            'client_id': client.client_id, 'client_secret': secret,
        })
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_resource_must_match_at_exchange(self):
        verifier, challenge = make_pkce()
        code = self.get_code(self.member, challenge)
        response = self.exchange(
            code, verifier, resource='https://other.example.com/mcp',
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_target')

    def test_foreign_resource_is_refused_at_authorize(self):
        _verifier, challenge = make_pkce()
        self.login(self.member)
        response = self.get(
            '/mcp/oauth/authorize',
            self.authorize_params(
                challenge, resource='https://other.example.com/mcp',
            ),
            allow_redirects=False,
        )
        query = parse_qs(urlsplit(response.headers['Location']).query)
        self.assertEqual(query['error'], ['invalid_target'])

    def test_token_is_bound_to_the_issuing_host(self):
        tokens = self.full_flow()
        self.assertEqual(self.ping_status(tokens['access_token']), 200)
        grant = self.env['skyward_mcp_oauth.grant'].search(
            [('user_id', '=', self.member.id)], limit=1,
        )
        self.assertEqual(grant.resource, self.base_url() + '/mcp')
        # Same rows copied to a database served elsewhere.
        grant.resource = 'https://prod.example.com/mcp'
        self.assertEqual(self.ping_status(tokens['access_token']), 401)

    def test_unsupported_grant_type(self):
        response = self.token_request(grant_type='password')
        self.assertEqual(response.json()['error'], 'unsupported_grant_type')

    # ----------------------------------------------------------
    # Tests: Refresh and revocation
    # ----------------------------------------------------------

    def test_refresh_rotates_both_tokens(self):
        tokens = self.full_flow()
        response = self.token_request(
            grant_type='refresh_token', refresh_token=tokens['refresh_token'],
        )
        self.assertEqual(response.status_code, 200, response.text)
        fresh = response.json()
        self.assertNotEqual(fresh['access_token'], tokens['access_token'])
        self.assertNotEqual(fresh['refresh_token'], tokens['refresh_token'])
        self.assertEqual(self.ping_status(fresh['access_token']), 200)
        self.assertEqual(self.ping_status(tokens['access_token']), 401)

    def test_refresh_retry_within_grace_window_is_tolerated(self):
        tokens = self.full_flow()
        self.token_request(
            grant_type='refresh_token', refresh_token=tokens['refresh_token'],
        )
        retry = self.token_request(
            grant_type='refresh_token', refresh_token=tokens['refresh_token'],
        )
        self.assertEqual(retry.status_code, 200, retry.text)
        self.assertEqual(self.ping_status(retry.json()['access_token']), 200)

    def test_reused_refresh_token_revokes_the_grant(self):
        self.env['ir.config_parameter'].sudo().set_param(
            'skyward_mcp_oauth.refresh_grace_seconds', '0',
        )
        tokens = self.full_flow()
        grant = self.env['skyward_mcp_oauth.grant'].search(
            [('user_id', '=', self.member.id)], limit=1,
        )
        fresh = self.token_request(
            grant_type='refresh_token', refresh_token=tokens['refresh_token'],
        ).json()
        grant.last_refresh = fields.Datetime.now() - timedelta(minutes=5)
        stale = self.token_request(
            grant_type='refresh_token', refresh_token=tokens['refresh_token'],
        )
        self.assertEqual(stale.status_code, 400)
        self.assertEqual(self.ping_status(fresh['access_token']), 401)

    def test_expired_access_token_is_refused_but_refreshable(self):
        tokens = self.full_flow()
        grant = self.env['skyward_mcp_oauth.grant'].search(
            [('user_id', '=', self.member.id)], limit=1,
        )
        grant.access_expires = fields.Datetime.now() - timedelta(minutes=1)
        self.assertEqual(self.ping_status(tokens['access_token']), 401)
        response = self.token_request(
            grant_type='refresh_token', refresh_token=tokens['refresh_token'],
        )
        self.assertEqual(response.status_code, 200)

    def test_expired_refresh_token_is_refused(self):
        tokens = self.full_flow()
        grant = self.env['skyward_mcp_oauth.grant'].search(
            [('user_id', '=', self.member.id)], limit=1,
        )
        grant.refresh_expires = fields.Datetime.now() - timedelta(minutes=1)
        response = self.token_request(
            grant_type='refresh_token', refresh_token=tokens['refresh_token'],
        )
        self.assertEqual(response.status_code, 400)

    def test_revoke_endpoint(self):
        tokens = self.full_flow()
        response = self.url_open('/mcp/oauth/revoke', data={
            'client_id': self.client.client_id,
            'token': tokens['refresh_token'],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.ping_status(tokens['access_token']), 401)

    def test_admin_revoke_action(self):
        tokens = self.full_flow()
        self.env['skyward_mcp_oauth.grant'].search(
            [('user_id', '=', self.member.id)],
        ).action_revoke()
        self.assertEqual(self.ping_status(tokens['access_token']), 401)

    # ----------------------------------------------------------
    # Tests: Audit log
    # ----------------------------------------------------------

    def audit_entries(self, event, status=None):
        domain = [('method', '=', 'oauth/%s' % event)]
        if status:
            domain.append(('status', '=', status))
        return self.env['muk_mcp.log'].sudo().search(domain)

    def test_events_are_audited(self):
        tokens = self.full_flow()
        self.assertTrue(self.audit_entries('authorize', 'ok'))
        self.assertTrue(self.audit_entries('token', 'ok').filtered(
            lambda log: log.user_id == self.member,
        ))
        self.token_request(
            grant_type='refresh_token', refresh_token=tokens['refresh_token'],
        )
        self.assertTrue(self.audit_entries('refresh', 'ok'))

    def test_refused_user_is_audited_without_secrets(self):
        _verifier, challenge = make_pkce()
        self.login(self.outsider)
        self.get(
            '/mcp/oauth/authorize', self.authorize_params(challenge),
            allow_redirects=False,
        )
        entry = self.audit_entries('authorize', 'denied')
        self.assertEqual(entry.user_id, self.outsider)
        self.assertNotIn(challenge, entry.request_data or '')

    # ----------------------------------------------------------
    # Tests: Access group
    # ----------------------------------------------------------

    def test_leaving_the_group_cuts_existing_tokens(self):
        tokens = self.full_flow()
        self.assertEqual(self.ping_status(tokens['access_token']), 200)
        self.member.write({
            'groups_id': [(3, self.env.ref(GROUP).id)],
        })
        self.assertEqual(self.ping_status(tokens['access_token']), 401)
        response = self.token_request(
            grant_type='refresh_token', refresh_token=tokens['refresh_token'],
        )
        self.assertEqual(response.status_code, 400)

    def test_archived_user_is_refused(self):
        tokens = self.full_flow()
        self.member.active = False
        self.assertEqual(self.ping_status(tokens['access_token']), 401)

    def test_manual_key_of_outsider_is_refused(self):
        token, _key = self.make_mcp_key(self.outsider)
        self.assertEqual(self.ping_status(token), 401)

    def test_manual_key_of_member_still_works(self):
        token, _key = self.make_mcp_key(self.member)
        self.assertEqual(self.ping_status(token), 200)

    def test_group_requirement_can_be_switched_off(self):
        self.env['ir.config_parameter'].sudo().set_param(
            'skyward_mcp_oauth.require_group', 'False',
        )
        token, _key = self.make_mcp_key(self.outsider)
        self.assertEqual(self.ping_status(token), 200)

    def test_only_members_can_generate_keys(self):
        wizard = self.env['muk_mcp.generate_key']
        with self.assertRaises(AccessError):
            wizard.with_user(self.outsider).create({'name': 'nope'})
        record = wizard.with_user(self.member).create({'name': 'ok'})
        self.assertTrue(record)

    def test_outsider_can_still_read_own_preferences(self):
        self.outsider.with_user(self.outsider).read(['mcp_key_ids'])

    # ----------------------------------------------------------
    # Tests: Dynamic registration
    # ----------------------------------------------------------

    def register(self, **body):
        return self.opener.post(
            self.base_url() + '/mcp/oauth/register', json=body, timeout=12,
        )

    def test_registration_is_off_by_default(self):
        response = self.register(redirect_uris=[REDIRECT])
        self.assertEqual(response.status_code, 404)

    def test_dynamic_registration(self):
        self.env['ir.config_parameter'].sudo().set_param(
            'skyward_mcp_oauth.allow_dynamic_registration', 'True',
        )
        meta = self.url_open('/.well-known/oauth-authorization-server').json()
        self.assertIn('registration_endpoint', meta)
        response = self.register(
            client_name='Dyn', redirect_uris=['https://dyn.example.com/cb'],
        )
        self.assertEqual(response.status_code, 201, response.text)
        created = self.env['skyward_mcp_oauth.client'].search(
            [('client_id', '=', response.json()['client_id'])],
        )
        self.assertTrue(created.dynamic and created.is_public)
        bad = self.register(redirect_uris=['http://evil.example.com/cb'])
        self.assertEqual(bad.status_code, 400)

    def test_identical_registrations_share_one_client(self):
        self.env['ir.config_parameter'].sudo().set_param(
            'skyward_mcp_oauth.allow_dynamic_registration', 'True',
        )
        body = {'client_name': 'Same', 'redirect_uris': ['https://s.example.com/cb']}
        first = self.register(**body).json()['client_id']
        second = self.register(**body).json()['client_id']
        self.assertEqual(first, second)
        other = self.register(
            client_name='Same', redirect_uris=['https://t.example.com/cb'],
        ).json()['client_id']
        self.assertNotEqual(first, other)

    def test_unused_dynamic_clients_are_vacuumed(self):
        Client = self.env['skyward_mcp_oauth.client']
        unused = Client.create({
            'name': 'Unused', 'is_public': True, 'dynamic': True,
            'redirect_uris': 'https://u.example.com/cb',
        })
        used = Client.create({
            'name': 'Used', 'is_public': True, 'dynamic': True,
            'redirect_uris': 'https://v.example.com/cb',
        })
        self.env['skyward_mcp_oauth.grant']._issue(
            used, self.member, 'read', self.base_url() + '/mcp',
        )
        old = fields.Datetime.now() - timedelta(days=2)
        self.env.cr.execute(
            "UPDATE skyward_mcp_oauth_client SET create_date = %s WHERE id IN %s",
            (old, (unused.id, used.id, self.client.id)),
        )
        Client.invalidate_model()
        Client._gc_dynamic_clients()
        self.assertFalse(unused.exists())
        self.assertTrue(used.exists())
        self.assertTrue(self.client.exists())

    # ----------------------------------------------------------
    # Tests: Consent screen
    # ----------------------------------------------------------

    def test_consent_screen_is_translated(self):
        self.env['res.lang']._activate_lang('es_AR')
        self.env['ir.module.module']._load_module_terms(
            ['skyward_mcp_oauth'], ['es_AR'],
        )
        self.member.lang = 'es_AR'
        _verifier, challenge = make_pkce()
        self.login(self.member)
        page = self.get(
            '/mcp/oauth/authorize', self.authorize_params(challenge),
        )
        self.assertIn('Conectar con MCP', page.text)
        self.assertIn('Permitir', page.text)
        self.assertIn('Denegar', page.text)

    def test_consent_screen_follows_the_login_layout(self):
        _verifier, challenge = make_pkce()
        self.login(self.member)
        page = self.get(
            '/mcp/oauth/authorize', self.authorize_params(challenge),
        )
        self.assertIn('oe_login_form', page.text)
        self.assertIn('oe_login_buttons', page.text)
        self.assertIn('Test Client', page.text)
