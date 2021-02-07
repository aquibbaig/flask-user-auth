import jwt
from flask_restful import Resource, abort
from flask import request, jsonify, make_response
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from models.models import UserModel, ActiveTokens
from database.database import Database
from auth.auth import Auth
from flask_bcrypt import check_password_hash

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

class LoginAPI(Resource):
  """
  Pbench API for User Login or generating an auth token
  """
  def __init__(self, auth):
    self.auth = auth
    self.token_expire_duration = "200"

  @Auth.token_auth.login_required(optional=True, f=Auth().verify_auth())
  def post(self):
    """
    Post request for logging in user.
    The user is allowed to re-login multiple times and each time a new valid auth token will
    be provided. This requires a JSON data with required user metadata fields
    {
        "username": "username",
        "password": "password",
    }
    Required headers include
      Content-Type:   application/json
      Accept:         application/json
    :return: JSON Payload
    if we succeed to decrypt the password hash, the returned response_object will
    include the auth_token
      response_object = {
        "status": "success", # will not present if failed
        "message": "Successfully logged in."/"failure message",
        "auth_token": auth_token.decode(), # Will not present if failed
      }
    """
    post_data = request.get_json()
    if not post_data:
      print("Invalid json object: {}", request.url)
      abort(400, message="Invalid json object in request")
    
    username = post_data.get("username")
    if not username:
      print("Username not provided during the login process")
      abort(400, message="Please provide a valid username")

    password = post_data.get("password")
    if not password:
      print("Password not provided during the login process")
      abort(400, message="Please provide a valid password")
    # Query the database
    try:
      user = UserModel.query.filter_by(username=username).first()
    except Exception as e:
      print(e)
      abort(500, message="INTERNAL ERROR")

    if not user:
      print(
          "No user found in the db for Username: {} while login", username
      )
      abort(403, message="No such user, please register first")
    
    # Validate the password
    try:
      check_password_hash(user.password, password)
    except Exception as e:
      print(e)
      abort(401, message="Bad login")
    # if not check_password_hash(user.password, password.encode('utf-8')):
    #   print("Wrong password for user: {} while login", username)
    #   abort(401, message="Bad login")
    try:
      auth_token = self.auth.encode_auth_token(
          self.token_expire_duration, user.id
      )
    except (
      jwt.InvalidIssuer,
      jwt.InvalidIssuedAtError,
      jwt.InvalidAlgorithmError,
      jwt.PyJWTError,
    ):
      print(
          "Could not encode the JWT auth token for user: {} while login", username
      )
      abort(
          500, message="INTERNAL ERROR",
      )
    # Add the new auth token to the database for later access
    try:
      token = ActiveTokens(token=auth_token.decode())
      token.user_id = user.id
      # TODO: Decide on the auth token limit per user

      # Adds a token for the user.
      Database.db_session.add(token)
      Database.db_session.commit()

      # user.query.update({user.auth_tokens: token})

      print("New auth token registered for user {}", user.email)
    except IntegrityError:
        print(
          "Duplicate auth token got created, user might have tried to re-login immediately"
        )
        abort(409, message="Retry login after some time")
    except SQLAlchemyError as e:
        print(
            "SQLAlchemy Exception while logging in a user {}", type(e)
        )
        abort(500, message="INTERNAL ERROR")
    except Exception:
        print("Exception while logging in a user")
        abort(500, message="INTERNAL ERROR")

    response_object = {
        "status": "success",
        "message": "Successfully logged in.",
        "auth_token": auth_token.decode(),
    }
    return make_response(jsonify(response_object), 200)