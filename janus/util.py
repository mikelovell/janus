from contextlib import contextmanager
from cStringIO import StringIO
import fcntl
import grp
import importlib
import os
import socket
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from paramiko import agent
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.message import Message
from paramiko.py3compat import byte_chr
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import SSHException

from janus import certificate

key_name_to_class = {
    'ssh-rsa': RSAKey,
    'ssh-dss': DSSKey,
    'ecdsa-sha2-nistp256': ECDSAKey,
    'ecdsa-sha2-nistp384': ECDSAKey,
    'ecdsa-sha2-nistp521': ECDSAKey,
    'RSA': RSAKey,
    'EC': ECDSAKey,
    'DSA': DSSKey,
}

@contextmanager
def flocked(filedescriptor):
    """ Locks FD before entering the context, always releasing the lock. """
    try:
        fcntl.flock(filedescriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(filedescriptor, fcntl.LOCK_UN)

def import_class(name):
    parts = name.rpartition('.')
    mod = importlib.import_module(parts[0])
    cls = getattr(mod, parts[2], None)
    if not cls:
        raise ImportError("{} in module {} not found".\
                          format(parts[2], parts[0]))
    return cls

def read_key_file(filepath, password=None):
    f = open(filepath, 'r')
    key_type = None
    for line in f:
        if line.startswith('-----BEGIN'):
            key_type = line.split()[1]
    f.seek(0)
    if not key_type:
        raise SSHException("Invalid key format")
    key_class = key_name_to_class.get(key_type)
    if not key_class:
        raise SSHException("Unknown key type {}".format(key_type))
    key = key_class.from_private_key(f, password)
    return key

class JanusContext(object):
    def __init__(self, username=None, groups=None,
                 req_source=None, req_addr=None):
        self.username = username
        self.groups = groups if groups else []
        self.req_source = req_source
        self.req_addr = req_addr

    @staticmethod
    def from_local_shell():
        username = os.getlogin()
        groups = []
        for group in grp.getgrall():
            if username in group.gr_mem:
                groups.append(group.gr_name)
        return JanusContext(username, groups, 'shell')

SSH2_AGENTC_ADD_IDENTITY = byte_chr(17)
SSH2_AGENTC_ADD_ID_CONSTRAINED = byte_chr(25)
SSH_AGENT_CONSTRAIN_LIFETIME = byte_chr(1)
SSH_AGENT_SUCCESS = 6

class JanusSSHAgent(agent.Agent):
    def __init__(self, sock_path):
        agent.AgentSSH.__init__(self)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sock_path)
        self.sock = sock
        self.sock_path = sock_path
        self._connect(self.sock)

    def add_key_cert(self, key, cert):
        if not key.can_sign():
            err = "Key cannot be used for signing or added to the agent {}"
            raise SSHException(err)

        if cert.valid_before < certificate.MAX_CERT_VALID_BEFORE:
            req_type = SSH2_AGENTC_ADD_ID_CONSTRAINED
            time_left = int(cert.valid_before - time.time())
        else:
            req_type = SSH2_AGENTC_ADD_IDENTITY
            time_left = None

        msg = Message()
        msg.add_byte(req_type)
        msg.add_string(cert.get_name())
        msg.add_string(cert.asbytes())

        if type(key) == RSAKey:
            # Convert private key to a cryptography key class. This is to get
            # around the variations in how paramiko handles keys internally
            buf = StringIO()
            key.write_private_key(buf)
            buf.seek(0)
            backend = default_backend()
            new_key = serialization.load_pem_private_key(str(buf.read()),
                                                         password=None,
                                                         backend=backend)
            priv_numbers = new_key.private_numbers()
            msg.add_mpint(priv_numbers.d)
            msg.add_mpint(priv_numbers.iqmp)
            msg.add_mpint(priv_numbers.p)
            msg.add_mpint(priv_numbers.q)
        elif type(key) == DSSKey:
            msg.add_mpint(key.x)
        elif type(key) == ECDSAKey:
            msg.add_mpint(key.signing_key.privkey.secret_multiplier)

        msg.add_string(cert.key_id)

        if time_left:
            msg.add_byte(SSH_AGENT_CONSTRAIN_LIFETIME)
            msg.add_int(time_left)

        restype, res = self._send_message(msg)
        if restype != SSH_AGENT_SUCCESS:
            return False
        return True
