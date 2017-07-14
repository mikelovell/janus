#!/usr/bin/python

import argparse
import base64
import getpass
import os
import sys
import traceback

import prettytable
import requests

from janus import certificate
from janus import shell

DEFAULT_URL = "http://localhost:3126"
DEFAULT_KEY_TYPE = 'rsa'
DEFAULT_KEY_BITS = 4096

class JanusRemoteClientV1(object):
    api_version = "v1"
    def __init__(self, baseurl, username=None, password=None):
        self.baseurl = baseurl
        self.username = username
        self.password = password

    def _request(self, resource, method='GET', body=None):
        url = "{base}/{version}/{resource}".format(base=self.baseurl,
                                                   version=self.api_version,
                                                   resource=resource)

        kwargs = {}
        kwargs['verify'] = 'cert.pem'
        kwargs['headers'] = {}
        if self.username and self.password:
            kwargs['auth'] = (self.username, self.password)

        if body:
            kwargs['json'] = body
            kwargs['headers']['Content-Type'] = 'application/json'

        req = requests.request(method, url, **kwargs)
        return req.json()

    def ca_list(self):
        return self._request("authorities")

    def cert_request(self, authority, cert_req):
        resource = "authorities/{0}/certificate".format(authority)
        return self._request(resource, method='POST', body=cert_req)

def cmd_remote_calist(args):
    client = JanusRemoteClientV1(args.url)
    calist = client.ca_list()
    if not isinstance(calist, list):
        raise Exception("API did not return a list of CAs")

    pt = prettytable.PrettyTable(field_names=['uuid', 'name', 'status'])
    for ca in calist:
        pt.add_row((ca['id'], ca['name'], ca['state']))

    print(pt)

def cmd_remote_certreq(args):
    try:
        ca_uuid = str(uuid.UUID(args.ca))
    except:
        ca_uuid = None

    if not (args.key_file or args.gen_key):
        err = "Either --key-file or --gen-key must be specified"
        raise Exception(err)

    if args.gen_key and not (args.key_file != None or args.ssh_add):
        err = "Either --key-file or --ssh-add must be specified for new key"
        raise Exception(err)

    if args.gen_key:
        key = shell.generate_key(args)
    else:
        key = shell.read_key_file(args)

    password = getpass.getpass()
    client = JanusRemoteClientV1(args.url, args.user, password)

    authorities = client.ca_list()
    authority = None
    for auth in authorities:
        if auth['name'] == args.ca:
            authority = auth
            break

        if ca_uuid and ca_uuid == auth['id']:
            authority = auth
            break

    if not authority:
        err = "Authority {} could not be found.".format(args.ca)
        raise Exception(err)

    cert_req = {}
    cert_req['publicKeyType'] = key.get_name()
    cert_req['publicKey'] = key.get_base64()
    if args.duration:
        cert_req['requestedDuration'] = args.duration
    if args.principals:
        cert_req['principals'] = args.principals
    else:
        cert_req['principals'] = [args.user]

    result = client.cert_request(authority['id'], cert_req)
#    if result.status_code != 200:
#        err = "Error requesting certificate. {0} {1}".format(result.status_code,
#                                                             result.reason)
#        raise Exception(err)

    print("New Cert ID {}".format(result['id']))
    print("{} {}".format(result['certificateKeyType'], result['certificate']))

    cert_data = base64.b64decode(result['certificate'])
    cert = certificate.SSHCertificate(data=cert_data)

    if args.gen_key and args.key_file:
        key.write_private_key_file(args.key_file)
    if args.key_file:
        shell.write_cert_file(args.key_file, cert)

    if args.ssh_add:
        res = shell.add_key_cert_to_agent(args, key, cert)
        if not res:
            err = "Error adding key to agent"
            raise Exception(err)
        print("Cert added to agent at {}".format(args.agent_sock))


def main():
    args = argparse.ArgumentParser(description='Janus Remote Cli')
    args.add_argument('--user', '-u', default=os.getlogin(),
                      help="Remote Username")
    args.add_argument('--url', '-r', default=DEFAULT_URL,
                      help="URL for remote endpoint")
    subargs = args.add_subparsers()

    args_calist = subargs.add_parser('ca-list')
    args_calist.set_defaults(func=cmd_remote_calist)

    auth_sock_path = os.environ.get('SSH_AUTH_SOCK')
    args_certreq = subargs.add_parser('cert-request')
    args_certreq.add_argument('--ca', '-c', required=True,
                              help="Certificate authority to request from")
    args_certreq.add_argument('--key-file', '-f',
                              help="Path to read or write private key from")
    args_certreq.add_argument('--gen-key', '-g', action='store_true',
                              help="Generate a new key")
    args_certreq.add_argument('--key-type', '-t', default=DEFAULT_KEY_TYPE,
                              help="Default key type. rsa, dsa, or ecdsa")
    args_certreq.add_argument('--bits', '-b', default=DEFAULT_KEY_BITS,
                              type=int,
                              help="Bits in key. Dependent on key type")
    args_certreq.add_argument('--ssh-add', '-a', action='store_true',
                              default=os.environ.has_key('SSH_AUTH_SOCK'),
                              help="Add new cert and key to an ssh-agent")
    args_certreq.add_argument('--agent-sock', '-s', default=auth_sock_path,
                              help="Path to read or write private key from")
    args_certreq.add_argument('--duration', '-d', type=int, default=2**64-1,
                              help="Duration, in seconds, for certificate")
    args_certreq.add_argument('--principals', '-p', nargs='*',
                              help="Request principals. " \
                                   "Can specifed multiple times.")
    args_certreq.set_defaults(func=cmd_remote_certreq)

    args = args.parse_args()
    try:
        args.func(args)
    except Exception as e:
        err = "Error."
        print(err)
        traceback.print_exc()
        return -1

if __name__ == "__main__":
    sys.exit(main())
