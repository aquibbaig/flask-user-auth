import jwt
import os
import datetime
from flask import request, abort
from flask_httpauth import HTTPTokenAuth
from models.models import UserModel, ActiveTokens
from database.database import Database

class Auth:
  token_auth = HTTPTokenAuth("Bearer")

  def encode_auth_token(self, token_expire_duration, user_id):
    """
    Generates the Auth Token
    :return: string
    """
    payload = {
      "iat": datetime.datetime.utcnow(),
      "exp": datetime.datetime.utcnow()
      + datetime.timedelta(minutes=int(token_expire_duration)),
      "sub": user_id,
    }

    # get jwt key.
    jwt_key = self.get_secret_key()
    return jwt.encode(payload, jwt_key, algorithm="HS256")

  def get_secret_key(self):
    try:
      return os.getenv("SECRET_KEY", "secret")
    except Exception as e:
      print(e)

  def verify_user(self, user, username):
    """
    Check if the provided username belong to the current user by
    querying the Usermodel with the current user
    :param username:
    :param logger
    :return: User (UserModel instance), verified status (boolean)
    """
    user = (
      Database.db_session.query(UserModel)
      .filter_by(id=self.token_auth.current_user().id)
      .first()
    )
    # check if the current username matches with the one provided
    verified = user is not None and user.username == username
    print("verified status of user '{}' is '{}'", username, verified)

    return user, verified

  def get_auth_token(self):
    # get auth token
    auth_header = request.headers.get("Authorization")
    if not auth_header:
      print("Missing expected Authorization header")
      abort(
        403,
        message="Please add 'Authorization' token as Authorization: Bearer <JWT_Auth_token>",
      )
    try:
      auth_schema, auth_token = auth_header.split()
    except ValueError:
      print("Malformed auth header during layout")
      abort(401, message="Please add 'Authorization' token as Authorization: Bearer <JWT_Auth_token>")

    else:
      if auth_schema.lower() != "bearer":
          print(
              "Expected authorization schema to be 'bearer', not '{}'",
              auth_schema,
          )
          abort(
              401,
              message="Malformed Authorization header, please add request header as Authorization: Bearer <session_token>",
          )
      return auth_token

  def verify_auth(self):
    @Auth.token_auth.verify_token
    def verify_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :param app:
        :return: integer|string
        """
        try:
          payload = jwt.decode(
            auth_token,
            os.getenv("SECRET_KEY", "my_precious"),
            algorithms="HS256",
          )
          user_id = payload["sub"]
          if ActiveTokens.valid(auth_token):
            user = UserModel.query.filter_by(id=user_id).first()
            return user
          return False
        except jwt.exceptions.ExpiredSignatureError:
          ActiveTokens.query.filter_by(token=auth_token).delete()
          Database.db_session.commit()
          print(
              "User attempted Pbench expired token '{}', Token deleted from the database and no longer tracked",
              auth_token,
          )
          return False
        except jwt.exceptions.InvalidTokenError:
          print(
              "User attempted invalid Pbench token '{}'", auth_token
          )
          return False
        except Exception:
          print(
              "Exception occurred while verifying the auth token '{}'", auth_token
          )
          return False

