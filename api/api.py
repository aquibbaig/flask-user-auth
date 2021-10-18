from modules.mailer import Mailer
import jwt
import os
from http import HTTPStatus
from flask_restful import Resource, abort
from flask import request, jsonify, make_response, current_app
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from models.models import UserModel, ActiveTokens
from flask_mail import Mail, Message
from database.database import Database
from auth.auth import Auth
from flask_bcrypt import check_password_hash

class ForgotPassword(Resource):
  def __init__(self, auth):
    self.mail = Mail(current_app)
    self.auth = auth

  """
    /forgot_password
  """
  def post(self):
    """
    Post request for initiating password recovery.
    This requires a JSON data with required user fields
    {
        "email": "user@domain.com"
    }

    Required headers include

        Content-Type:   application/json
        Accept:         application/json

    :return:
        Success: 200 with password reset link sent to email
        Failure: <status_Code>,
                response_object = {
                    "message": "failure message"
                }
    """
    # get the post data
    print("Here")
    user_data = request.get_json()
    if not user_data:
      print("Invalid json object: {}", request.url)
      abort(HTTPStatus.BAD_REQUEST, message="Invalid json object in request")

    email = user_data.get("email")
    if not email:
      print("Missing email field")
      abort(HTTPStatus.BAD_REQUEST, message="Missing email field")

    # Check if email exists in the Db, else abort
    try:
      user = UserModel.query.filter_by(email=email).first()
    except Exception:
      print("Exception while querying email")
      abort(HTTPStatus.INTERNAL_SERVER_ERROR, message="INTERNAL ERROR")

    if not user:
      print("No such user exists with the given email ID")
      return "", HTTPStatus.OK

    # generate auth token for the valid user
    token = self.auth.encode_auth_token("60", user.id)

    # generate email and send to the user
    # Ideally the message should be a template
    # rendered using render_template
    body = "Please reset your password at http://localhost:8000/reset_password/" + str(token)
    msg = Message(subject="Reset your password!",
                  sender=os.environ.get('EMAIL_USER'),
                  recipients=[email],
                  body=body
                  )

    self.mail.send(msg)

    return "", HTTPStatus.OK

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
     abort(HTTPStatus.BAD_REQUEST, message="Invalid json object in request")

   username = user_data.get("email")
   if not username:
     print("Missing username field")
     abort(
         HTTPStatus.BAD_REQUEST, message="Missing username field",
     )
   username = username.lower()
   if username == "admin":
     print("User tried to register with admin username")
     abort(
         HTTPStatus.BAD_REQUEST, message="Please choose another username",
     )

   password = user_data.get("password")
   if not password:
     print("Missing password field")
     abort(
         HTTPStatus.BAD_REQUEST, message="Missing password field",
     )

   emailID = user_data.get("email")
   if not emailID:
     print("Missing email field")
     abort(
         HTTPStatus.BAD_REQUEST, message="Missing email field",
     )

   firstName = user_data.get("first_name")
   if not firstName:
     print("Missing firstName field")
     abort(
         HTTPStatus.BAD_REQUEST, message="Missing firstName field",
     )

   lastName = user_data.get("last_name")
   if not lastName:
     print("Missing lastName field")
     abort(
         HTTPStatus.BAD_REQUEST, message="Missing lastName field",
     )

   # validate the email field
   try:
     valid = validate_email(emailID)
     email = valid.email
   except EmailNotValidError:
     print("Invalid email {}", emailID)
     abort(HTTPStatus.BAD_REQUEST, message=f"Invalid email: {emailID}")

   # check if user already exist
   user = UserModel.query.filter_by(username=user_data.get("username")).first()
   if user:
     print(
         "A user tried to re-register. Username: {}", user.username
     )
     abort(HTTPStatus.UNAUTHORIZED, message="A user with that name already exists.")

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

     return "", HTTPStatus.CREATED
   except Exception:
     print("Exception while registering a user")
     Database.db_session.rollback()
     abort(HTTPStatus.INTERNAL_SERVER_ERROR, message="INTERNAL ERROR")

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
     abort(HTTPStatus.BAD_REQUEST, message="Invalid json object in request")

   username = post_data.get("username")
   if not username:
     print("Username not provided during the login process")
     abort(HTTPStatus.BAD_REQUEST, message="Please provide a valid username")

   password = post_data.get("password")
   if not password:
     print("Password not provided during the login process")
     abort(HTTPStatus.BAD_REQUEST, message="Please provide a valid password")
   # Query the database
   try:
     user = UserModel.query.filter_by(username=username).first()
     print("==============")
     print(user)
     print("==============")
   except Exception as e:
     print(e)
     abort(HTTPStatus.INTERNAL_SERVER_ERROR, message="INTERNAL ERROR")

   if not user:
     print(
         "No user found in the db for Username: {} while login", username
     )
     abort(HTTPStatus.UNAUTHORIZED, message="No such user, please register first")

   # Validate the password
   try:
     check_password_hash(user.password, password)
   except Exception as e:
     print(e)
     abort(HTTPStatus.UNAUTHORIZED, message="Bad login")
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
         HTTPStatus.INTERNAL_SERVER_ERROR, message="INTERNAL ERROR",
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
       abort(HTTPStatus.CONFLICT, message="Retry login after some time")
   except SQLAlchemyError as e:
       print(
           "SQLAlchemy Exception while logging in a user {}", type(e)
       )
       abort(HTTPStatus.INTERNAL_SERVER_ERROR, message="INTERNAL ERROR")
   except Exception:
       print("Exception while logging in a user")
       abort(HTTPStatus.INTERNAL_SERVER_ERROR, message="INTERNAL ERROR")

   print("==============")
   print(auth_token)
   print("==============")

   response_object = {
     "auth_token": auth_token.decode('utf-8'),
     "username": username,
   }
   return make_response(jsonify(response_object), HTTPStatus.OK)

class SendRecoveryEmail(Resource):
  def __init__(self):
    print("Init api")

  def post(self):
    post_data = request.get_json()
    if not post_data:
      print("Invalid json object: {}", request.url)
      abort(HTTPStatus.BAD_REQUEST, message="Invalid json object in request")
    email = post_data.get("email")
    print(email)

    # send an email to this account
    mailer = Mailer()
    mailer.send_email(email, "hello!")

    response_object = {
      "redirect_url": "url://token"
    }
    return make_response(jsonify(response_object), HTTPStatus.OK)
