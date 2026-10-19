"""One process per Part 3 service. Run from the shared project root."""
import argparse
from common import runtime as rt
from part3.incidents import register as incidents
from part3.playbooks import register as playbooks
from part3.reports import register as reports


def create_app(service):
    register = {'incidents': incidents, 'reports': reports, 'playbooks': playbooks}[service]
    app = rt.make_app(service)
    # Flask's automatic static endpoint would have an unprefixed route.
    from werkzeug.routing import Map
    app.url_map = Map()
    app.view_functions.pop('static', None)
    register(app, rt.prefix('part3'))
    return app


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('service', choices=('incidents', 'reports', 'playbooks'))
    service = parser.parse_args().service
    create_app(service).run(host='127.0.0.1', port=rt.CONFIG['ports'][service], debug=False)
