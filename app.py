import os
from flask import Flask
from flask_restful import Resource, Api
from api.api import RegisterUser, LoginAPI
from flask_cors import CORS
from auth.auth import Auth

from database.database import Database

app = Flask(__name__)
api = Api(app)
CORS(app)

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
api.add_resource(LoginAPI, '/session', resource_class_args=(token_auth,))
api.add_resource(RegisterUser, '/user')

if __name__ == '__main__':
  app.run(debug=True)
