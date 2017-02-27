import base64
import os
import uuid

from janus import util

class BaseDataStore(object):
    def __init__(self, **kw_args):
        raise NotImplementedError

    def get_next_serial(self):
        raise NotImplementedError

    def add_certificate(self, cert):
        raise NotImplementedError

    def list_certificates(self):
        raise NotImplementedError

class InMemoryDataStore(BaseDataStore):
    def __init__(self, **kwargs):
        self.certs = {}
        self.next_serial = 1

    def get_next_serial(self):
        serial = self.next_serial
        self.next_serial += 1
        return serial

    def add_certificate(self, cert):
        cert_id = uuid.uuid4()
        self.certs[cert_id] = cert
        return cert_id

class DirectoryDataStore(BaseDataStore):
    def __init__(self, **kwargs):
        ca_name = kwargs.get('ca_name', None)
        base_directory = kwargs.get('base_directory', None)
        if not ca_name or not base_directory:
            err = "ca_name or base_directory not provided"
            raise Exception(err)
        self.dir = os.path.join(base_directory, ca_name)
        self.serial_file = os.path.join(self.dir, 'serial')
        if not os.path.isdir(self.dir):
            os.mkdir(self.dir)
            os.chmod(self.dir, 0700)
            with open(self.serial_file, 'w') as serfile:
                serfile.write("{}\n".format(1))

    def get_next_serial(self):
        with open(self.serial_file, 'r+') as serfile:
            with util.flocked(serfile):
                cur_serial = int(serfile.readline().strip())
                new_serial = cur_serial + 1
                serfile.seek(0)
                serfile.write("{}\n".format(new_serial))
        return cur_serial

    def add_certificate(self, cert):
        cert_id = uuid.uuid4()
        cert_path = os.path.join(self.dir, "{}.pub".format(cert_id))
        with open(cert_path, 'w') as cert_file:
            cert_file.write("{} ".format(cert.get_name()))
            cert_file.write(base64.b64encode(cert.asbytes()))
            cert_file.write("\n")
        return cert_id

