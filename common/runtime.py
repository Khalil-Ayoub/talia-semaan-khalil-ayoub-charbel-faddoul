"""Shared integration contract. Keep identical in all three deliveries."""
import functools
import hmac
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, current_app, g, jsonify, request
from werkzeug.exceptions import HTTPException

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / 'team_config.json').read_text(encoding='utf-8'))
ADMIN = 'Security Administrator'
ANALYST = 'Security Analyst'
EMPLOYEE = 'Regular Employee/User'
AUDITOR = 'Auditor'
LEVELS = ('Low', 'Medium', 'High', 'Critical')
LOGIN_SUCCESS_ACTION = 'login_succeeded'
LOGIN_FAILURE_ACTION = 'login_failed'
MAX_SQLITE_INTEGER = 2**63 - 1


def now():
    return datetime.now(timezone.utc).isoformat()


def prefix(part):
    name = CONFIG['owners'][part]
    return '/' + re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')


def url(service, path=''):
    part = {'users':'part2','logs':'part2','notifications':'part2',
            'assets':'part1','threats':'part1','vulnerabilities':'part1',
            'incidents':'part3','reports':'part3','playbooks':'part3'}[service]
    return f"http://127.0.0.1:{CONFIG['ports'][service]}{prefix(part)}{path}"


class APIError(Exception):
    def __init__(self, message, code=400):
        self.message, self.code = message, code


def db():
    if 'db' not in g:
        path = Path(os.environ.get('PROJECT_DB', ROOT / 'data' / 'project.db'))
        path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(path, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db


def make_app(service):
    app = Flask(service, static_folder=None)
    @app.teardown_appcontext
    def close(_error):
        connection = g.pop('db', None)
        if connection is not None:
            connection.close()
    @app.errorhandler(APIError)
    def api_error(error):
        return jsonify(status='error', message=error.message), error.code
    @app.errorhandler(sqlite3.IntegrityError)
    def integrity_error(_error):
        return jsonify(status='error', message='Duplicate record or a related record prevents this operation'), 409
    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(status='error', message=error.description), error.code
    @app.errorhandler(Exception)
    def unexpected(error):
        app.logger.exception('Unexpected service error')
        return jsonify(status='error', message='Internal server error'), 500
    with app.app_context():
        db().executescript((ROOT / 'common' / 'schema.sql').read_text())
    return app


def service_headers():
    secret = os.environ.get('SERVICE_SECRET')
    if not secret:
        raise APIError('Set SERVICE_SECRET for inter-service calls', 503)
    return {'X-Service-Key': secret}


def internal_only(func):
    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        expected = os.environ.get('SERVICE_SECRET', '')
        supplied = request.headers.get('X-Service-Key', '')
        if not expected:
            raise APIError('Service authentication is not configured', 503)
        if not hmac.compare_digest(expected, supplied):
            raise APIError('Invalid service credentials', 401)
        return func(*args, **kwargs)
    return wrapped


def call(service, method, path, payload=None, internal=False):
    headers = service_headers() if internal else {'Authorization': request.headers.get('Authorization', '')}
    try:
        response = requests.request(method, url(service, path), json=payload, headers=headers, timeout=5)
        result = response.json()
    except (requests.RequestException, ValueError) as error:
        raise APIError(f'{service} service is unavailable', 503) from error
    if response.status_code >= 400:
        raise APIError(result.get('message', f'{service} request failed'), response.status_code)
    return result.get('data', result)


def audit(action, description, severity='Information'):
    return call('logs', 'POST', '/internal/logs', {
        'user_id': getattr(g, 'user', {}).get('id'), 'action': action,
        'description': description, 'severity': severity,
        'related_service': current_app.name
    }, internal=True)


def protected(*roles):
    def decorate(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            token = request.headers.get('Authorization', '')
            if not token.startswith('Bearer ') or not token[7:].strip():
                g.user = {}
                audit('Unauthorized access', 'Missing authentication token', 'Warning')
                raise APIError('Authentication required', 401)
            g.user = call('users', 'POST', '/internal/verify', {'token': token[7:]}, internal=True)
            if g.user.get('role') not in roles:
                audit('Unauthorized access', 'Role does not permit this operation', 'Warning')
                raise APIError('User does not have permission to perform this operation', 403)
            return func(*args, **kwargs)
        return wrapped
    return decorate


def body(required=(), allowed=None):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data:
        raise APIError('A non-empty JSON object is required')
    if allowed is not None and set(data) - set(allowed):
        raise APIError('Unexpected fields: ' + ', '.join(sorted(set(data) - set(allowed))))
    for key in required:
        if key not in data or data[key] is None or (isinstance(data[key], str) and not data[key].strip()):
            raise APIError(f'{key} is required')
    return data


def text(data, key):
    if key in data:
        if not isinstance(data[key], str) or not data[key].strip() or len(data[key]) > 4000:
            raise APIError(f'{key} must be non-empty text of at most 4000 characters')
        data[key] = data[key].strip()


def choice(data, key, values):
    if key in data and data[key] not in values:
        raise APIError(f'{key} must be one of: ' + ', '.join(values))


def positive_id(value, name='id'):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_SQLITE_INTEGER:
        raise APIError(f'{name} must be an integer between 1 and {MAX_SQLITE_INTEGER}')


def fetch(table, record_id):
    positive_id(record_id)
    row = db().execute(f'SELECT * FROM {table} WHERE id=?', (record_id,)).fetchone()
    if row is None:
        raise APIError('Record not found', 404)
    return dict(row)


def ok(data, code=200):
    return jsonify(status='success', data=data), code
