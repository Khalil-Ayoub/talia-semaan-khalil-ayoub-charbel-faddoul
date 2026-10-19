"""Small shared helpers; cross-service calls always occur outside write transactions."""
from flask import g
from common import runtime as rt


def deny(message):
    rt.audit('Unauthorized access', message, 'Warning')
    raise rt.APIError(message, 403)


def active_user(user_id, analyst=False):
    rt.positive_id(user_id, 'user_id')
    if user_id == g.user['id']:
        user = g.user
    else:
        user = rt.call('users', 'GET', f'/internal/users/{user_id}', internal=True)
    if user.get('account_status') != 'Active' or user.get('deleted_at'):
        raise rt.APIError('Assigned/referenced user must be Active')
    if analyst and user.get('role') != rt.ANALYST:
        raise rt.APIError('Assigned account must be an Active Security Analyst')
    return user


def requested(action, description):
    rt.audit(action + ' requested', description + '; validated request, not a completion record')


def rows(query, values=()):
    return [dict(r) for r in rt.db().execute(query, values)]


def insert(table, data):
    # Only module-owned literals and validated keys reach SQL identifiers.
    cursor = rt.db().execute(
        f"INSERT INTO {table} ({','.join(data)}) VALUES ({','.join('?' for _ in data)})",
        tuple(data.values()))
    return cursor.lastrowid


def strings(data, keys):
    for key in keys:
        rt.text(data, key)
