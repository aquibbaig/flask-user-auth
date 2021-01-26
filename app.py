import os
from flask import Flask
from flask_restful import Resource, Api

from database.database import Database

app = Flask(__name__)
api = Api(app)

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

if __name__ == '__main__':
  app.run(debug=True)
