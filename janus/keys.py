import base64
import socket
import os

from paramiko import agent as ParamikoAgent

from janus import util

class KeyBackend(object):
    def __init__(self, **kwargs):
        self.key = None
        self.pub_key = None
        self.pub_key_comment = None

    def sign_cert(self, cert):
        nonce = os.urandom(32)
        cert.sign(self.key, nonce)

    def _read_pub_key(self, pub_key_file):
        with open(pub_key_file, 'r') as pub_file:
            pub_parts = pub_file.readline().split()

        if len(pub_parts) < 2:
            err = "Invalid format in keyfile {}".format(pub_key_file)
            raise Exception(err)
        if pub_parts[0] not in util.key_name_to_class.keys():
            err = "Unknown key type in public key {}".format(pub_key_file)
            raise Exception(err)
        pub_key_class = util.key_name_to_class.get(pub_parts[0])
        pub_key = pub_key_class(data=base64.b64decode(pub_parts[1]))
        if len(pub_parts) >= 3:
            self.pub_key_comment = ' '.join(pub_parts[2:])
        return pub_key_class, pub_key

    def is_online(self):
        return True

    def pubkey(self):
        key_b64 = base64.b64encode(self.pub_key.asbytes())
        if self.pub_key_comment:
            return self.pub_key.get_name(), key_b64, self.pub_key_comment
        else:
            return self.pub_key.get_name(), key_b64, ''

class KeyFileBackend(KeyBackend):
    def __init__(self, key_file, pub_key_file, **kwargs):
        pub_key_class, pub_key = self._read_pub_key(pub_key_file)

        priv_key = pub_key_class.from_private_key_file(key_file)
        if pub_key != priv_key:
            err = "Mismatching keys for {} {}".format(key_file, pub_key_file)
            raise Exception(err)

        self.key = priv_key
        self.pub_key = pub_key

class AgentKeyBackend(KeyBackend):
    def __init__(self, **kwargs):
        if 'agent_sock' not in kwargs.keys() or \
           'pub_key_file' not in kwargs.keys():
            err = "agent_sock and pub_key_file required"
            raise Exception(err)
        pub_key_class, pub_key = self._read_pub_key(kwargs['pub_key_file'])
        self.pub_key = pub_key

        self._agent = util.JanusSSHAgent(kwargs['agent_sock'])

        self.key = None
        for key in self._agent.get_keys():
            if key.asbytes() == pub_key.asbytes():
                self.key = key
                self.key.can_sign = self.returnTrue

        if not self.key:
            err = "Key matching {} not found in socket {}".\
                   format(kwargs['pub_key_file'], kwargs['agent_sock'])
            raise Exception(err)

    def returnTrue(self):
        return True
