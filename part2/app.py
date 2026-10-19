"""Command-line entry point for Part 2's users, logs, and notifications APIs."""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
from pathlib import Path

from flask import Blueprint, Flask, request

from part2.core import ApiProblem, failure, handle_problem
from part2.logs import register_log_routes
from part2.notifications import register_notification_routes
from part2.users import register_user_routes

REGISTRARS = {
    "users": register_user_routes,
    "logs": register_log_routes,
    "notifications": register_notification_routes,
}


def _prefix() -> str:
    try:
        runtime = importlib.import_module("common.runtime")
        helper = getattr(runtime, "prefix")
        try:
            value = helper("part2")
        except TypeError:
            value = helper()
        return "/" + str(value).strip("/")
    except (ImportError, AttributeError, TypeError):
        config = json.loads(Path("team_config.json").read_text(encoding="utf-8"))
        return "/" + "-".join(config["owners"]["part2"].lower().split())


def _shared_app(service: str) -> Flask:
    try:
        try:
            factory = getattr(importlib.import_module("common"), "make_app")
        except (ImportError, AttributeError):
            factory = getattr(importlib.import_module("common.runtime"), "make_app")
    except (ImportError, AttributeError):
        return Flask(f"part2-{service}")
    if inspect.signature(factory).parameters:
        return factory(service)
    return factory()


def create_app(service: str) -> Flask:
    if service not in REGISTRARS:
        raise ValueError("service must be users, logs, or notifications")
    app = _shared_app(service)
    blueprint = Blueprint(f"part2_{service}", __name__)
    REGISTRARS[service](blueprint)
    app.register_blueprint(blueprint, url_prefix=_prefix())

    @app.before_request
    def validate_route_ids():
        from part2.core import require_id
        for key, value in (request.view_args or {}).items():
            if isinstance(value, int):
                require_id(value, key)

    @app.errorhandler(ApiProblem)
    def api_problem(error: ApiProblem):
        return handle_problem(error)

    @app.errorhandler(404)
    def not_found(_error):
        return failure("Resource not found", 404)

    @app.errorhandler(500)
    def internal_error(_error):
        return failure("The request could not be completed", 500)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one Part 2 service")
    parser.add_argument("service", choices=tuple(REGISTRARS))
    service = parser.parse_args().service
    port = {"users": 5001, "logs": 5005, "notifications": 5008}[service]
    create_app(service).run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()