from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from odoo import http
from odoo.exceptions import ValidationError
from odoo.http import request
from odoo.tools.misc import str2bool

from ..models.oauth_code import OAuthError

NO_STORE = [('Cache-Control', 'no-store'), ('Pragma', 'no-cache')]
MAX_DYNAMIC_CLIENTS = 200


class MCPOAuthController(http.Controller):

    # ----------------------------------------------------------
    # Helper
    # ----------------------------------------------------------

    def _base_url(self):
        return request.env['skyward_mcp_oauth.base'].get_base_url()

    def _json(self, data, status=200, headers=None):
        return request.make_json_response(
            data, status=status, headers=NO_STORE + (headers or []),
        )

    def _json_error(self, exc):
        body = {'error': exc.error}
        if exc.description:
            body['error_description'] = exc.description
        headers = []
        if exc.status == 401:
            headers.append(('WWW-Authenticate', 'Basic realm="mcp"'))
        return self._json(body, status=exc.status, headers=headers)

    def _redirect(self, uri, **params):
        parts = urlsplit(uri)
        query = parse_qsl(parts.query, keep_blank_values=True)
        query += [(k, v) for k, v in params.items() if v]
        target = urlunsplit(parts._replace(query=urlencode(query)))
        return request.redirect(target, code=303, local=False)

    def _frame_guard(self, response):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
        response.headers['Cache-Control'] = 'no-store'
        return response

    def _error_page(self, exc):
        response = request.render('skyward_mcp_oauth.error', {
            'error': exc.error,
            'description': exc.description,
        })
        response.status_code = 400
        return self._frame_guard(response)

    def _client(self):
        return request.env['skyward_mcp_oauth.client'].sudo()

    def _audit(self, event, status='ok', user=None, key=None, detail=None):
        request.env['skyward_mcp_oauth.base'].audit(
            event, status=status, user=user, key=key, detail=detail,
        )

    def _client_from_credentials(self, kw):
        auth = request.httprequest.authorization
        client_id = (auth.username if auth else None) or kw.get('client_id')
        secret = (auth.password if auth else None) or kw.get('client_secret')
        client = self._client().search(
            [('client_id', '=', client_id or '')], limit=1,
        )
        if not client or not client._verify_secret(secret):
            raise OAuthError('invalid_client', "Client authentication failed.", 401)
        return client

    # ----------------------------------------------------------
    # Metadata
    # ----------------------------------------------------------

    @http.route(
        [
            '/.well-known/oauth-protected-resource',
            '/.well-known/oauth-protected-resource/mcp',
        ],
        type='http', auth='public', methods=['GET', 'OPTIONS'],
        csrf=False, cors='*', readonly=True,
    )
    def protected_resource(self, **kw):
        base = self._base_url()
        return request.make_json_response({
            'resource': '%s/mcp' % base,
            'authorization_servers': [base],
            'bearer_methods_supported': ['header'],
            'scopes_supported': ['mcp:read', 'mcp:write'],
        })

    @http.route(
        '/.well-known/oauth-authorization-server',
        type='http', auth='public', methods=['GET', 'OPTIONS'],
        csrf=False, cors='*', readonly=True,
    )
    def authorization_server(self, **kw):
        base = self._base_url()
        metadata = {
            'issuer': base,
            'authorization_endpoint': '%s/mcp/oauth/authorize' % base,
            'token_endpoint': '%s/mcp/oauth/token' % base,
            'revocation_endpoint': '%s/mcp/oauth/revoke' % base,
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': [
                'none', 'client_secret_post', 'client_secret_basic',
            ],
            'scopes_supported': ['mcp:read', 'mcp:write'],
        }
        if self._dynamic_registration_enabled():
            metadata['registration_endpoint'] = '%s/mcp/oauth/register' % base
        return request.make_json_response(metadata)

    def _dynamic_registration_enabled(self):
        return str2bool(
            request.env['ir.config_parameter'].sudo().get_param(
                'skyward_mcp_oauth.allow_dynamic_registration', 'False',
            ),
            default=False,
        )

    # ----------------------------------------------------------
    # Authorization endpoint
    # ----------------------------------------------------------

    @http.route(
        '/mcp/oauth/authorize',
        type='http', auth='public', methods=['GET', 'POST'],
        csrf=True, save_session=True,
    )
    def authorize(self, **kw):
        client = self._client().search(
            [('client_id', '=', kw.get('client_id') or '')], limit=1,
        )
        redirect_uri = kw.get('redirect_uri')
        if not client or not client._check_redirect_uri(redirect_uri):
            return self._error_page(OAuthError(
                'invalid_request', "Unknown client or redirect URI.",
            ))
        state = kw.get('state')

        def fail(error, description):
            return self._redirect(
                redirect_uri, error=error,
                error_description=description, state=state,
            )

        if kw.get('response_type') != 'code':
            return fail('unsupported_response_type', "Only code is supported.")
        challenge = kw.get('code_challenge')
        if not challenge or kw.get('code_challenge_method') != 'S256':
            return fail('invalid_request', "PKCE with S256 is required.")
        audience = '%s/mcp' % self._base_url()
        resource = (kw.get('resource') or '').rstrip('/')
        if resource and resource != audience:
            return fail('invalid_target', "Unknown resource.")
        requested = (kw.get('scope') or '').split()
        offers_write = client.allow_write and 'mcp:write' in requested

        user = request.env.user
        if user._is_public():
            if request.httprequest.method != 'GET':
                return fail('access_denied', "Not signed in.")
            return request.redirect('/web/login?%s' % urlencode({
                'redirect': request.httprequest.full_path,
            }))
        if not request.env['muk_mcp.key']._user_allowed(user):
            self._audit(
                'authorize', 'denied', user,
                detail="%s: user not allowed" % client.name,
            )
            return fail('access_denied', "This user is not allowed to use MCP.")

        if request.httprequest.method == 'POST':
            if kw.get('decision') != 'approve':
                self._audit(
                    'authorize', 'denied', user,
                    detail="%s: user denied" % client.name,
                )
                return fail('access_denied', "The user denied the request.")
            # The user may narrow what the client asked for, never widen it.
            scope = 'write' if (
                offers_write and kw.get('grant_write') == '1'
            ) else 'read'
            self._audit(
                'authorize', 'ok', user,
                detail="%s: %s" % (client.name, scope),
            )
            code = request.env['skyward_mcp_oauth.code']._issue(
                client, user, redirect_uri, challenge, scope, audience,
            )
            return self._redirect(redirect_uri, code=code, state=state)

        response = request.render('skyward_mcp_oauth.consent', {
            'client': client,
            'user': user,
            'offers_write': offers_write,
            'fields': {
                key: kw.get(key) or '' for key in (
                    'client_id', 'redirect_uri', 'response_type', 'state',
                    'code_challenge', 'code_challenge_method', 'scope',
                    'resource',
                )
            },
        })
        return self._frame_guard(response)

    # ----------------------------------------------------------
    # Token endpoint
    # ----------------------------------------------------------

    @http.route(
        '/mcp/oauth/token',
        type='http', auth='public', methods=['POST'],
        csrf=False, save_session=False,
    )
    def token(self, **kw):
        env = request.env
        try:
            client = self._client_from_credentials(kw)
            grant_type = kw.get('grant_type')
            if grant_type == 'authorization_code':
                code = env['skyward_mcp_oauth.code']._consume(
                    kw.get('code'), client,
                    kw.get('redirect_uri'), kw.get('code_verifier'),
                )
                resource = (kw.get('resource') or '').rstrip('/')
                if resource and resource != code.resource:
                    raise OAuthError('invalid_target', "Unknown resource.")
                if not env['muk_mcp.key']._user_allowed(code.user_id):
                    raise OAuthError(
                        'invalid_grant', "This user is not allowed to use MCP.",
                    )
                scope = code.scope if client.allow_write else 'read'
                grant, tokens = env['skyward_mcp_oauth.grant']._issue(
                    client, code.user_id, scope, code.resource,
                )
                code.write({'used': True, 'grant_id': grant.id})
                self._audit(
                    'token', 'ok', code.user_id, grant.key_id,
                    detail="%s: %s" % (client.name, scope),
                )
            elif grant_type == 'refresh_token':
                grant, tokens = env['skyward_mcp_oauth.grant']._refresh(
                    kw.get('refresh_token'), client,
                )
                self._audit(
                    'refresh', 'ok', grant.user_id, grant.key_id,
                    detail=client.name,
                )
            else:
                raise OAuthError('unsupported_grant_type')
        except OAuthError as exc:
            self._audit(
                'token', 'denied',
                detail="%s: %s" % (kw.get('client_id'), exc.error),
            )
            return self._json_error(exc)
        return self._json(tokens)

    @http.route(
        '/mcp/oauth/revoke',
        type='http', auth='public', methods=['POST'],
        csrf=False, save_session=False,
    )
    def revoke(self, **kw):
        try:
            self._client_from_credentials(kw)
        except OAuthError as exc:
            return self._json_error(exc)
        request.env['skyward_mcp_oauth.grant']._revoke_by_token(kw.get('token'))
        self._audit('revoke', detail=kw.get('client_id'))
        return self._json({})

    # ----------------------------------------------------------
    # Dynamic client registration
    # ----------------------------------------------------------

    @http.route(
        '/mcp/oauth/register',
        type='http', auth='public', methods=['POST'],
        csrf=False, save_session=False,
    )
    def register(self, **kw):
        if not self._dynamic_registration_enabled():
            return self._json({'error': 'registration_not_supported'}, 404)
        try:
            data = request.get_json_data()
        except Exception:
            data = None
        if not isinstance(data, dict):
            return self._json({'error': 'invalid_client_metadata'}, 400)
        uris = data.get('redirect_uris')
        if not (isinstance(uris, list) and uris
                and all(isinstance(uri, str) for uri in uris)):
            return self._json({'error': 'invalid_redirect_uri'}, 400)
        clients = self._client()
        if clients.search_count([('dynamic', '=', True)]) >= MAX_DYNAMIC_CLIENTS:
            return self._json({'error': 'temporarily_unavailable'}, 429)
        name = str(data.get('client_name') or 'MCP client')[:80]
        redirect_uris = '\n'.join(uris)
        # Clients register again on every connection attempt; a public client
        # holds no secret, so identical metadata can share one registration.
        client = clients.search([
            ('dynamic', '=', True), ('name', '=', name),
            ('redirect_uris', '=', redirect_uris),
        ], limit=1)
        if not client:
            try:
                client = clients.create({
                    'name': name,
                    'is_public': True,
                    'dynamic': True,
                    'redirect_uris': redirect_uris,
                })
            except ValidationError:
                return self._json({'error': 'invalid_redirect_uri'}, 400)
        self._audit('register', detail=client.name)
        return self._json({
            'client_id': client.client_id,
            'client_name': client.name,
            'redirect_uris': uris,
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'none',
        }, status=201)
