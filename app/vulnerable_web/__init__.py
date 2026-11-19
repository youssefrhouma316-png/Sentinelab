from flask import Flask


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = "development-only-secret"

    from app.vulnerable_web.routes import web

    app.register_blueprint(web)

    return app