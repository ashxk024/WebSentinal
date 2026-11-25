"""WebSentinel Flask entry point.

Stage 1 exposes a health check and a target validation API. The dashboard
arrives in Stage 7.
"""
import logging
from dataclasses import asdict
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, request

from config import Config
from scanner.target_validator import TargetPolicy, check_connectivity, validate_target

__version__ = "0.1.0"


def configure_logging(config=Config) -> None:
    """Log to the console and a rotating file, never logging request bodies."""
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    handlers = [
        logging.StreamHandler(),
        RotatingFileHandler(
            config.LOG_DIR / "websentinel.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        ),
    ]
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def create_app(config_class=Config, policy=None) -> Flask:
    """Application factory."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    target_policy = policy or TargetPolicy.from_config(config_class)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "version": __version__})

    @app.post("/api/validate")
    def validate():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or "url" not in payload:
            return jsonify({"error": "JSON body with a 'url' field is required."}), 400

        result = validate_target(payload["url"], payload.get("authorized") is True, target_policy)
        body = {"validation": result.to_dict()}
        if not result.valid:
            return jsonify(body), 400
        if payload.get("check_connectivity") is True:
            body["connectivity"] = asdict(check_connectivity(result.url, target_policy))
        return jsonify(body), 200

    return app


if __name__ == "__main__":
    configure_logging()
    create_app().run(host=Config.HOST, port=Config.PORT, debug=False)
