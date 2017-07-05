#!/usr/bin/python

import argparse
import base64
from ConfigParser import SafeConfigParser
import json
import uuid
from wsgiref import simple_server

import falcon
from passlib.apache import HtpasswdFile

from janus.authority import SSHCertAuthorityManager
from janus import certificate
from janus import util

DEFAULT_CONFIG = 'example.conf'
V1_URL_BASE = '/v1'
version_data = [
    {'version': 1,
     'path': V1_URL_BASE,
     'date': '2017-03',
     'updated': '2017-03',
    },
]

class BasicAuthMiddleware(object):
    def __init__(self, htpasswd_path):
        self.path = htpasswd_path

    def process_request(self, req, resp):
        auth_header = req.get_header('Authorization')
        if not auth_header:
            return

        header_parts = auth_header.split()
        if len(header_parts) != 2:
            err = "Invalid Authorization Header"
            raise falcon.HTTPBadRequest('400 Bad Request', err)

        if header_parts[0].lower() != 'basic':
            err = "Only Basic Authentication is supported. Not {0}".format(header_parts[0])
            raise falcon.HTTPBadRequest('400 Bad Request', err)

        try:
            decoded = base64.b64decode(header_parts[1]).decode('utf-8')
            user, password = decoded.split(':', 1)
        except:
            err = "Error decoding Authorization Header"
            raise falcon.HTTPBadRequest('400 Bad Request', err)

        try:
            auth_db = HtpasswdFile(self.path)
        except:
            err = "Auth database offline"
            raise falcon.HTTPServiceUnavailable('503 Unavail', err)

        res = auth_db.check_password(user, password)
        if not res:
            err = "Invalid Username and/or Password"
            raise falcon.HTTPUnauthorized('401 Unauthorized', err, ['Basic'])

        req.context['user'] = user

class JanusContextMiddleware(object):
    def process_request(self, req, resp):
        username = req.context.get('user', None)
        ctx = util.JanusContext(username=username,
                                req_source=req.protocol,
                                req_addr=req.remote_addr)
        req.context['janus_context'] = ctx

class Jsonify(object):
    supported_types = ['application/json',
                       'application/text',
                       None]

    def process_request(self, req, resp):
        print("Content-Type: {0}".format(req.content_type))
        if req.content_type not in self.supported_types:
            return

        if req.content_length == 0:
            return

        try:
            body = req.stream.read()
            data = json.loads(body)
            req.context['json'] = data
        except (ValueError, UnicodeDecodeError):
            err = "Count not decode valid json"
            raise falcon.HTTPBadRequest('400 Bad Request', err)

    def process_response(self, req, resp, resource):
        if 'data' not in req.context:
            return

        resp.body = json.dumps(req.context['data'])
        resp.content_type = 'application/json'

class ApiResource(object):
    def on_get(self, req, resp):
        req.context['data'] = version_data

class CAManagerResource(object):
    def __init__(self, manager):
        self.manager = manager

class AuthorityCollection(CAManagerResource):
    def on_get(self, req, resp):
        req.context['data'] = self.manager.list_authorities()

class AuthorityResource(CAManagerResource):
    def on_get(self, req, resp, authority_id):
        authority = self.manager.authorities.get(authority_id)
        if not authority:
            err = "Authority Not Found"
            raise falcon.HTTPNotFound("404 Not Found", err)

        keytype, keyb64, comment = authority.get_pubkey()
        res = {'id': authority_id,
               'name': authority.ca_name,
               'state': 'Online' if authority.is_online() else 'Offline',
               'publicKeyType': keytype,
               'publicKey': "{0} {1}".format(keyb64, comment)}

        req.context['data'] = res

class CertificateResource(CAManagerResource):
    def on_post(self, req, resp, authority_id):
        ctx = req.context.get('janus_context')
        if not ctx:
            err = "Context Not Found"
            raise falcon.HTTPInternalServerError("500 Error", err)

        if not ctx.username:
            err = "Unauthenticated requests are not allowed"
            raise falcon.HTTPUnauthorized('401 Unauthorized', err, ['Basic'])

        authority = self.manager.authorities.get(authority_id)
        if not authority:
            err = "Authority Not Found"
            raise falcon.HTTPNotFound("404 Not Found", err)

        req_data = req.context.get('json')
        if not req_data:
            err = "Request did not contain json"
            raise falcon.HTTPBadRequest("400 Bad Request", err)

        pub_key_type = req_data.get('publicKeyType')
        pub_key = req_data.get('publicKey')
        if not pub_key_type or not pub_key:
            err = "publicKeyType and/or publicKey not specified"
            raise falcon.HTTPBadRequest("400 Bad Request", err)

        key_class = util.key_name_to_class.get(pub_key_type)
        if not key_class:
            err = "Unknown publicKeyClass {0}".format(pub_key_type)
            raise falcon.HTTPBadRequest("400 Bad Request", err)

        cert_request = {}
        cert_request['publicKeyType'] = pub_key_type
        cert_request['publicKey'] = pub_key
        cert_request['requestedDuration'] = req_data.get('requestedDuration',
                                            certificate.MAX_CERT_VALID_BEFORE)
        if not isinstance(cert_request['requestedDuration'], (int, long)):
            err = "Duration must be an integer"
            raise falcon.HTTPBadRequest("400 Bad Request", err)

        cert_request['certificateType'] = req_data.get('certificateType',
                                             certificate.SSH_CERT_TYPE_USER)
        principals = req_data.get('principals', [ctx.username])
        if type(principals) != list:
            err = "Principals must be a list"
            raise falcon.HTTPBadRequest("400 Bad Request", err)

        for princ in principals:
            if not isinstance(princ, (str, unicode)):
                err = "All principals must be string. Not {0}".format(princ)
                raise falcon.HTTPBadRequest("400 Bad Request", err)

        cert_request['principals'] = principals
        extensions = req_data.get('extensions')
        if not extensions:
            extensions = {'permit-X11-forwarding': '',
                          'permit-agent-forwarding': '',
                          'permit-port-forwarding': '',
                          'permit-pty': '',
                          'permit-user-rc': '',}
        cert_request['extensions'] = extensions

        try:
            cert_id, cert = authority.process_request(ctx, cert_request)
        except Exception as E:
            err = "Error Processing Request"
            raise falcon.HTTPInternalServerError("500 Error", err)

        cert_resp = {}
        cert_resp['id'] = str(cert_id)
        cert_resp['state'] = 'Signed'
        cert_resp['certificateKeyType'] = cert.get_name()
        cert_resp['certificate'] = base64.b64encode(cert.asbytes())
        req.context['data'] = cert_resp

def build_app(config_file):
    cfg = SafeConfigParser()
    res = cfg.read(config_file)
    manager = SSHCertAuthorityManager.from_configparser(cfg)

    if not cfg.has_section("janus:api"):
        err = "Config File does not specify janus:api section"
        raise Exception(err)

    if not cfg.has_option("janus:api", "passwd_file"):
        err = "Config does not specify path to auth file"
        raise Exception(err)

    auth_path = cfg.get("janus:api", "passwd_file")

    auth_middleware = BasicAuthMiddleware(auth_path)
    ctx_middleware = JanusContextMiddleware()
    app = falcon.API(middleware=[Jsonify(),auth_middleware, ctx_middleware])
    app.add_route('/', ApiResource())

    authorities_route = "{0}/authorities".format(V1_URL_BASE)
    authorities_collection = AuthorityCollection(manager)
    app.add_route(authorities_route, authorities_collection)

    authority_route = "{0}/authorities/{{authority_id}}".format(V1_URL_BASE)
    authority_resource = AuthorityResource(manager)
    app.add_route(authority_route, authority_resource)

    certificate_route = "{0}/certificate".format(authority_route)
    certificate_resource = CertificateResource(manager)
    app.add_route(certificate_route, certificate_resource)

    return app

if __name__ == "__main__":
    args = argparse.ArgumentParser(description='Simple Janus testapp')
    args.add_argument('--config-file', default='example.conf',
                      help='Path to the janus config file')
    args = args.parse_args()

    app = build_app(args.config_file)
    server = simple_server.make_server('127.0.0.1', 8000, app)
    server.serve_forever()
