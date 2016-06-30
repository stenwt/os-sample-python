from flask import Flask
application = Flask(__name__)

from rauth.service import OAuth2Service

@application.route("/")
def hello():
    return "Hello World!"

if __name__ == "__main__":
    application.run()
