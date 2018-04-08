#!/usr/bin/env python2

import argparse
import base64
from ConfigParser import SafeConfigParser
from cStringIO import StringIO
import getpass
import os
import sys
import traceback
import uuid

from ecdsa import curves

from paramiko.agent import Agent
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import PasswordRequiredException

HAS_EVENTLET = False
try:
    import eventlet
    from eventlet import wsgi as eventlet_wsgi
    HAS_EVENTLET = True
except ImportError:
    pass

from janus import api
from janus.authority import SSHCertAuthorityManager
from janus import certificate
from janus import util

DEFAULT_CONFIG = 'example.conf'
DEFAULT_KEY_TYPE = 'rsa'
DEFAULT_KEY_BITS = 4096

def generate_key(args):
    key_class = None
    if args.key_type == 'rsa':
        key_class = RSAKey
        key_args = [args.bits]
    elif args.key_type == 'dsa':
        key_class = DSSKey
        key_args = [args.bits]
    elif args.key_type == 'ecdsa':
        key_class = ECDSAKey
        key_curve = getattr(curves, "NIST{}p".format(args.bits))
        key_args = [key_curve]

    if not key_class:
        err = "Invalid key type {}.".format(args.key_type)
        raise Exception(err)

    return key_class.generate(*key_args)

def read_key_file(args):
    try:
        key = util.read_key_file(args.key_file)
    except PasswordRequiredException:
        p = getpass.getpass("Password for {}: ".format(args.key_file))
        key = util.read_key_file(args.key_file, password=p)
    return key

def write_cert_file(path, cert):
    cert_path = "{}-cert.pub".format(path)
    cert_file = open(cert_path, 'w')
    cert_b64 = base64.b64encode(cert.asbytes())
    cert_file.write("{} {}".format(cert.get_name(), cert_b64))
    cert_file.close()
    print("Certificate written to {}".format(cert_path))

def add_key_cert_to_agent(args, key, cert):
    if not args.agent_sock:
        err = "Agent socket not provided"
        raise Exception(err)

    agent = util.JanusSSHAgent(args.agent_sock)
    return agent.add_key_cert(key, cert)

def find_ca(manager, name_or_id):
    try:
        ca_is_uuid = uuid.UUID(name_or_id)
    except:
        ca_is_uuid = False

    if ca_is_uuid:
        return manager.authorities.get(name_or_id)
    else:
        authorities = manager.list_authorities()
        for a in authorities:
            if a['name'] == name_or_id:
                return manager.authorities.get(a['id'])

def cmd_calist(args):
    authorities = args.manager.list_authorities()
    fstr = "UUID: {id} Name: {name} State: {state}"
    for authority in authorities:
        print(fstr.format(**authority))

def cmd_certreq(args):
    if not (args.key_file or args.gen_key):
        err = "Either --key-file or --gen-key must be specified"
        raise Exception(err)

    if args.gen_key and not (args.key_file != None or args.ssh_add):
        err = "Either --key-file or --ssh-add must be specified for new key"
        raise Exception(err)

    authority = find_ca(args.manager, args.ca)
    if not authority:
        err = "Authority {} count not be found.".format(args.ca)
        raise Exception(err)

    if args.gen_key:
        key = generate_key(args)
    else:
        key = read_key_file(args)

    context = util.JanusContext.from_local_shell()
    request = {}
    request['publicKeyType'] = key.get_name()
    request['publicKey'] = base64.b64encode(key.asbytes())
    request['requestedDuration'] = args.duration
    if args.cert_type == 'user':
        request['certificateType'] = certificate.SSH_CERT_TYPE_USER
        request['extensions'] = {'permit-X11-forwarding': '',
                                 'permit-agent-forwarding': '',
                                 'permit-port-forwarding': '',
                                 'permit-pty': '',
                                 'permit-user-rc': '', }
        if not args.principals:
            request['principals'] = [context.username]

    elif args.cert_type == 'host':
        request['certificateType'] = certificate.SSH_CERT_TYPE_HOST
        if not args.principals:
            raise Exception("You must specify principals for a host key")
    else:
        # Can't happen right now, but just in case some new cert type
        # comes out and we add to to argparse but not here.
        raise Exception("Cannot handle {} certificate type.".format(
            args.cert_type))

    if args.principals:
        request['principals'] = args.principals

    cert_id, cert = authority.process_request(context, request)
    print("New Cert ID {}.".format(cert_id))
    cert_b64 = base64.b64encode(cert.asbytes())
    print("{} {}".format(cert.get_name(), cert_b64))

    if args.gen_key and args.key_file:
        key.write_private_key_file(args.key_file)
    if args.key_file:
        write_cert_file(args.key_file, cert)

    if args.ssh_add:
        res = add_key_cert_to_agent(args, key, cert)
        if not res:
            err = "Error adding key to agent"
            raise Exception(err)
        print("Cert added to agent at {}".format(args.agent_sock))

def cmd_capubkey(args):
    authority = find_ca(args.manager, args.ca)
    if not authority:
        err = "Authority {} count not be found.".format(args.ca)
        raise Exception(err)

    keytype, keyb64, comment = authority.get_pubkey()
    key = "{} {} {}".format(keytype, keyb64, comment)
    print(key)

    if args.key_file:
        key_file = open(args.key_file, 'w')
        key_file.write(key)
        key_file.close()
        print("Public key written to {}".format(args.key_file))

def cmd_serve(args):
    if not HAS_EVENTLET:
        raise Exception("python-eventlet is required to run api server" \
                        "through the cli. Try installing it or running" \
                        "through another WSGI server")

    sock = eventlet.listen((args.listen, args.port))
    ssl_sock = eventlet.wrap_ssl(sock, server_side=True,
                                 certfile=args.ssl_cert,
                                 keyfile=args.ssl_key)
    app = api.build_app(args.config_file)
    eventlet_wsgi.server(ssl_sock, app, keepalive=False)

def main():
    args = argparse.ArgumentParser(description='Simple Janus Cli')
    args.add_argument('--config-file', default=DEFAULT_CONFIG,
                      help='Path to the janus config file')
    subargs = args.add_subparsers()

    args_calist = subargs.add_parser('ca-list')
    args_calist.set_defaults(func=cmd_calist)

    args_capubkey = subargs.add_parser('ca-pubkey')
    args_capubkey.add_argument('--ca', '-c', required=True,
                               help="Certificate authority to request from")
    args_capubkey.add_argument('--key-file', '-f',
                               help="Path to write the pubkey to.")
    args_capubkey.set_defaults(func=cmd_capubkey)

    auth_sock_path = os.environ.get('SSH_AUTH_SOCK')
    args_certreq = subargs.add_parser('cert-request')
    args_certreq.add_argument('--ca', '-c', required=True,
                              help="Certificate authority to request from")
    args_certreq.add_argument('--cert-type', '-e', choices=['host', 'user'],
                              default='user',
                              help="Request either a host or user "
                                   "certificate.")
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
    args_certreq.set_defaults(func=cmd_certreq)

    args_serve = subargs.add_parser('serve')
    args_serve.add_argument('--listen', '-l', default='127.0.0.1',
                            help="Address to listen on")
    args_serve.add_argument('--port', '-p', type=int, default=3126,
                            help="Port to listen on")
    args_serve.add_argument('--ssl-cert', required=True,
                            help="Port to listen on")
    args_serve.add_argument('--ssl-key', required=True,
                            help="Port to listen on")
    args_serve.set_defaults(func=cmd_serve)

    args = args.parse_args()

    cfg = SafeConfigParser()
    res = cfg.read(args.config_file)
    if not res:
        err = "Error reading config file {}\n".format(args.config_file)
        print(err)
        return -1

    try:
        manager = SSHCertAuthorityManager.from_configparser(cfg)
        args.manager = manager
    except Exception as excp:
        err = "Error creating manager. {}".format(excp)
        print(err)
        traceback.print_exc()
        return -1

    try:
        args.func(args)
    except Exception as excp:
        err = "Error in request. {}".format(excp)
        print(err)
        traceback.print_exc()
        return -1

if __name__ == "__main__":
    sys.exit(main())

# vim: ts=4 expandtab
