import werkzeug

from odoo import models
from odoo.http import request


class IrHttp(models.AbstractModel):

    _inherit = 'ir.http'

    @classmethod
    def _handle_error(cls, exception):
        response = super()._handle_error(exception)
        if (
            getattr(request, 'dispatcher', None)
            and request.dispatcher.routing_type == 'mcp'
            and isinstance(exception, werkzeug.exceptions.Unauthorized)
        ):
            base = request.env['skyward_mcp_oauth.base'].get_base_url()
            response.headers['WWW-Authenticate'] = (
                'Bearer realm="mcp", resource_metadata="%s/.well-known/'
                'oauth-protected-resource"' % base
            )
        return response
