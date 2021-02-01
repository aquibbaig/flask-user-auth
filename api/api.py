import jwt
from flask_restful import Resource, abort
from flask import request, jsonify, make_response
from email_validator import validate_email, EmailNotValidError
from models.models import UserModel
from database.database import Database

class RegisterUser(Resource):
  """
  Abstracted pbench API for registering a new user
  """
  def __init__(self):
    # Sets token expiry
    print("Init api")
  def post(self):
    """
    Post request for registering a new user.
    This requires a JSON data with required user fields
    {
        "username": "username",
        "password": "password",
        "firstName": first_name,
        "lastName": "last_name",
        "email": "user@domain.com"
    }
    Required headers include
      Content-Type:   application/json
      Accept:         application/json
    :return: JSON Payload
    if we succeed to add a user entry in database, the returned response_object will look like following:
      response_object = {
        "status": "success", # not present if the request fails
        "message": "Successfully registered."/"failure message",
      }
    To get the auth token user has to perform the login action
    """
    # get the post data
    user_data = request.get_json()
    if not user_data:
      print("Invalid json object: {}", request.url)
      abort(400, message="Invalid json object in request")

    username = user_data.get("username")
    if not username:
      print("Missing username field")
      abort(
          400, message="Missing username field",
      )
    username = username.lower()
    if username == "admin":
      print("User tried to register with admin username")
      abort(
          400, message="Please choose another username",
      )

    password = user_data.get("password")
    if not password:
      print("Missing password field")
      abort(
          400, message="Missing password field",
      )

    emailID = user_data.get("email")
    if not emailID:
      print("Missing email field")
      abort(
          400, message="Missing email field",
      )

    firstName = user_data.get("firstName")
    if not firstName:
      print("Missing firstName field")
      abort(
          400, message="Missing firstName field",
      )

    lastName = user_data.get("lastName")
    if not lastName:
      print("Missing lastName field")
      abort(
          400, message="Missing lastName field",
      )

    # validate the email field
    try:
      valid = validate_email(emailID)
      email = valid.email
    except EmailNotValidError:
      print("Invalid email {}", emailID)
      abort(400, message=f"Invalid email: {emailID}")

    # check if user already exist
    user = UserModel.query.filter_by(username=user_data.get("username")).first()
    if user:
      print(
          "A user tried to re-register. Username: {}", user.username
      )
      abort(403, message="A user with that name already exists.")

    try:
      user = UserModel(
          bcrypt_log_rounds=None,
          username=username,
          password=password,
          firstName=firstName,
          lastName=lastName,
          email=email,
      )

      # insert the user
      Database.db_session.add(user)
      Database.db_session.commit()
      print(
          "New user registered, username: {}, email: {}", username, email
      )

      response_object = {
          "status": "success",
          "message": "Successfully registered.",
      }
      response = jsonify(response_object)
      response.status_code = 201
      return make_response(response, 201)
    except Exception:
      print("Exception while registering a user")
      Database.db_session.rollback()
      abort(500, message="INTERNAL ERROR")

