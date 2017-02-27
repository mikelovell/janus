from contextlib import contextmanager
from cStringIO import StringIO
import fcntl
import importlib
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from paramiko import agent
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.message import Message
from paramiko.py3compat import byte_chr
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import SSHException

key_name_to_class = {
    'ssh-rsa': RSAKey,
    'ssh-dss': DSSKey,
    'ecdsa-sha2-nistp256': ECDSAKey,
    'ecdsa-sha2-nistp384': ECDSAKey,
    'ecdsa-sha2-nistp521': ECDSAKey,
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

SSH2_AGENTC_ADD_IDENTITY = byte_chr(17)
SSH2_AGENTC_ADD_ID_CONSTRAINED = byte_chr(25)
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

        # for future key adding with contstraints
        #if cert.valid_before < certificate.MAX_CERT_VALID_BEFORE:
        #    msg_type = SSH2_AGENTC_ADD_IDENTITY
        #    expiration = cert.valid_before
        #    time_left = int(expiration - time.time())
        #else:
        #    msg_type = SSH2_AGENTC_ADD_ID_CONSTRAINED
        #    time_left = None
        msg_type = SSH2_AGENTC_ADD_IDENTITY

        msg = Message()
        msg.add_byte(msg_type)
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
        # future: add constraint

        restype, res = self._send_message(msg)
        if restype != SSH_AGENT_SUCCESS:
            return False
        return True
