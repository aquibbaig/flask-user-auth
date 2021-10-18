import os
from flask import current_app as app
from flask_mail import Mail, Message

# Mailer -> mail
# Mailer, mail, this.mail

class Mailer:
  def __init__(self):
    self.mail = Mail(app)
  def send_email (self, recipient, message):
    try:
      msg = Message(subject="Hello",
        sender=app.config.get("MAIL_USERNAME"),
        recipients=[recipient],
        body=message)
      self.mail.send(msg)
    except Exception as e:
      print(e)
