import datetime
from dateutil import parser
from flask_bcrypt import generate_password_hash
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from database.database import Database
from sqlalchemy.orm import relationship


class UserModel(Database.Base):
    """ User Model for storing user related details """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), unique=True, nullable=False)
    firstName = Column(String(255), unique=False, nullable=False)
    lastName = Column(String(255), unique=False, nullable=False)
    password = Column(String(255), nullable=False)
    registered_on = Column(DateTime, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    auth_tokens = relationship("ActiveTokens", backref="users")

    def __init__(self, bcrypt_log_rounds, **kwargs):
        super().__init__(**kwargs)
        self.username = kwargs.get("username")
        self.firstName = kwargs.get("firstName")
        self.lastName = kwargs.get("lastName")
        self.password = generate_password_hash(
            kwargs.get("password"), bcrypt_log_rounds
        )
        self.email = kwargs.get("email")
        self.registered_on = datetime.datetime.now()

    def __str__(self):
        return f"User, id: {self.id}, username: {self.username}"

    def is_admin(self):
        # TODO: Add notion of Admin user
        """this method would always return false for now until we add a notion of Admin user/group.
        Once we know the admin credentials this method can check against those credentials to determine
        whether the user is privileged to do more.
        This can be extended to groups as well for example a user belonging to certain group has only those
        privileges that are assigned to the group.
        """
        return False

    # TODO: Add password recovery mechanism


class ActiveTokens(Database.Base):
    """Token model for storing the active auth tokens at any given time"""

    __tablename__ = "active_tokens"
    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(500), unique=True, nullable=False, index=True)
    created = Column(DateTime, nullable=False)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        # no need to add index=True, all FKs have indexes
    )

    def __init__(self, token):
        self.token = token
        self.created = datetime.datetime.now()

    @staticmethod
    def valid(auth_token):
        # check whether auth token is in the active database
        res = ActiveTokens.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False


class Metadata(Database.Base):
    """ Metadata Model for storing user metadata details """

    # TODO: Think about the better name
    __tablename__ = "metadata"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created = Column(DateTime, nullable=False)
    updated = Column(DateTime, nullable=False)
    config = Column(String(255), unique=False, nullable=False)
    description = Column(String(255), nullable=False)

    def __init__(self, created, config, description):
        self.created = parser.parse(created)
        self.updated = datetime.datetime.now()
        self.config = config
        self.description = description

    def __str__(self):
        return f"Url id: {self.id}, created on: {self.created}, description: {self.description}"
