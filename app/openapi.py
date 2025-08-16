from flask_restx import Api, Resource, fields
from app.main import app

api = Api(app, version='1.0', title='Omni Gerador de Artigos API',
          description='Documentação OpenAPI dos principais endpoints do sistema.')

webhook_model = api.model('Webhook', {
    'url': fields.String(required=True, description='URL do webhook para notificação')
})

@api.route('/webhook')
class WebhookResource(Resource):
    @api.doc('register_webhook')
    @api.expect(webhook_model)
    def post(self):
        """Cadastra um novo webhook para notificação ao final da geração."""
        return '', 501  # Not Implemented

@api.route('/status/<string:trace_id>')
class StatusResource(Resource):
    @api.doc('get_status')
    def get(self, trace_id):
        """Consulta o status de uma geração pelo trace_id."""
        return '', 501  # Not Implemented

# Adicione outros endpoints relevantes conforme necessário 