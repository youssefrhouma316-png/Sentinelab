from flask import Flask, request, g
from time import perf_counter

from collectors.security_logger import log_http_event


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = "development-only-secret"

    @app.before_request
    def start_request_timer():
        g.request_start_time = perf_counter()

    @app.after_request
    def log_request(response):
        start_time = getattr(g, "request_start_time", perf_counter())
        duration_ms = (perf_counter() - start_time) * 1000

        log_http_event(
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            source_ip=request.remote_addr or "unknown",
            user_agent=request.user_agent.string or "unknown",
            duration_ms=duration_ms,
        )

        return response

    from app.vulnerable_web.routes import web
    app.register_blueprint(web)

    return app