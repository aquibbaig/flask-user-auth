import os
from flask import Flask
from flask_restful import Resource, Api
from api.api import RegisterUser, LoginAPI, SendRecoveryEmail, ForgotPassword
from flask_cors import CORS
from auth.auth import Auth
from flask_mail import Mail
 
from database.database import Database
 
app = Flask(__name__)
api = Api(app)
CORS(app)

# sets up email configuration
mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": os.environ.get('EMAIL_USER'),
    "MAIL_PASSWORD": os.environ.get('EMAIL_PASSWORD')
}
app.config.update(mail_settings)

mail = Mail(app)
 
token_auth = Auth()
 
# Connect to db
try:
 Database.init_db()
except Exception as e:
 print(e)
 print("Could not initialise database")
class HomeRoute(Resource):
 def get(self):
   return "Hello World"
 
api.add_resource(HomeRoute, '/')
 
# LoginAPI
api.add_resource(LoginAPI, '/login', resource_class_args=(token_auth,))
api.add_resource(RegisterUser, '/register')
api.add_resource(
    ForgotPassword, '/forgot-password', resource_class_args=(token_auth,),
)

# Recovery email.
api.add_resource(SendRecoveryEmail, '/recovery_email')
 
if __name__ == '__main__':
 app.run(debug=True)
