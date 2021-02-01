from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
import sys

class Database:
  # Create declarative base model that our model can inherit from
  Base = declarative_base()
  # Initialize the db scoped session
  db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False))

  @staticmethod
  def init_engine():
    try:
      # Creates an engine with the URI.
      engine = create_engine("postgresql://postgres:pwd@127.0.0.1/testdb")
      return engine
    except Exception as e:
      print(e)
      print("Error occurred while initialising engine")
      sys.exit(1)

  @staticmethod
  def init_db():
    try:
      Database.Base.query = Database.db_session.query_property()
      engine = Database.init_engine()
      Database.Base.metadata.create_all(engine)
      Database.db_session.configure(bind=engine)

      print("Connected to db")
    except Exception as e:
      print(e)
      print("Error occurred while connecting to db.")
      sys.exit(1)
