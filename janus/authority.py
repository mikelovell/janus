import base64
import datetime
import os
import socket
import time
import uuid

from paramiko import agent as ParamikoAgent
from paramiko.transport import Transport

from janus import certificate
from janus import util

AUTHORITY_NAMESPACE = uuid.UUID('b3dae8d1-f992-11e6-ac70-cfdeb7070182')

class SSHCertRequestException(Exception):
    pass

class SSHCertRequestNotAllowed(Exception):
    pass

class SSHCertAuthority(object):
    def __init__(self, ca_name, ca_key, data_store, filters=None):
        self.ca_name = ca_name
        self.key = ca_key
        self.ds = data_store
        if filters:
            self.filters = filters
        else:
            self.filters = []

    def is_online(self):
        return self.key.is_online()

    def get_pubkey(self):
        return self.key.pubkey()

    def process_request(self, ctx, req):
        key_type = req.get('publicKeyType')
        if not key_type or key_type not in util.key_name_to_class.keys():
            err = "publicKeyType not specified or unknown"
            raise SSHCertRequestException(err)

        key_data = req.get('publicKey')
        if not key_data:
            err = "publicKey not specified"
            raise SSHCertRequestException(err)
        try:
            key_data = base64.b64decode(key_data)
            key_class = util.key_name_to_class.get(key_type)
            key = key_class(data=key_data)
        except Exception as e:
            err = "Unable to decode publicKey. {}".format(e)
            raise SSHCertRequestException(err)

        cert_req = certificate.SSHCertificate(key=key)
        cert_req.type = req.get('certificateType') 
        date_stamp = datetime.datetime.utcnow().strftime("%Y%m%d:%H%M%S")
        name = "{}-{}-{}-cert".format(ctx.get('username'),
                                      self.ca_name, date_stamp)
        cert_req.key_id = name

        start_time = time.time()
        duration = req.get('requestedDuration', 0)
        if duration:
            expiration = start_time + duration
        else:
            expiration = certificate.MAX_CERT_VALID_BEFORE
        cert_req.valid_after = start_time
        cert_req.valid_before = expiration

        cert_req.principals = req.get('principals', [])

        crit_opts = req.get('criticalOptions', {})
        for key in crit_opts.keys():
            cert_req.set_critical_option(key, crit_opts[key])

        exts = req.get('extensions', {})
        for key in exts.keys():
            cert_req.extensions[key] = exts[key]

        request_modified = False
        delay_signing = False
        for req_filter in self.filters:
            allowed, modified, delayed = req_filter.process(ctx, cert_req)
            if not allowed:
                err = "Request not allowed by {}".format(req_filter.name)
                raise SSHCertRequestNotAllowed(err)
            request_modified = request_modified or modified
            delay_signing = delay_signing or delayed

        cert_req.serial = self.ds.get_next_serial()

        if not delay_signing:
            self.key.sign_cert(cert_req)
            cert_id = self.ds.add_certificate(cert_req)
            return cert_id, cert_req
        else:
            raise Exception("Delayed certs not yet supported")

    @staticmethod
    def from_configparser(cfg, section):
        ca_name = section[3:]  #strip the ca_
        if not cfg.has_option(section, 'key_class'):
            err = "key_class not defined for ca {}".format(ca_name)
            raise Exception(err)

        config_dict = dict(cfg.items(section))
        if 'ca_name' not in config_dict.keys():
            config_dict['ca_name'] = ca_name
        key_class = cfg.get(section, 'key_class')
        key_class = util.import_class(key_class)
        ca_key = key_class(**config_dict)

        if not cfg.has_option(section, 'data_store'):
            err = "data_store not defined for ca {}".format(ca_name)
            raise Exception(err)

        data_store_class = cfg.get(section, 'data_store')
        data_store_class = util.import_class(data_store_class)
        data_store = data_store_class(**config_dict)

        req_filters = []
        if cfg.has_option(section, 'filters'):
            filter_str = cfg.get(section, 'filters', '')
            filters = filter_str.split(',')
        else:
            filters = []
        for filt_name in filters:
            filter_section = "filter_{}".format(filt_name)
            if not cfg.has_section(filter_section):
                err = "Config for filter {} not found".format(filt_name)
                raise Exception(err)
            if not cfg.has_option(filter_section, 'class'):
                err = "class not defined for filter {}".format(filt_name)
                raise Exception(err)
            filter_cls = util.import_class(cfg.get(filter_section, 'class'))
            filter_config = dict(cfg.items(filter_section))
            new_filter = filter_cls(**filter_config)
            req_filters.append(new_filter)

        return SSHCertAuthority(ca_name, ca_key, data_store, req_filters)

class SSHCertAuthorityManager(object):
    def __init__(self, authorities):
        self.authorities = authorities

    def list_authorities(self):
        res = []
        for authority_id, authority in self.authorities.items():
            ca_data = {'id': authority_id, 'name': authority.ca_name,
                       'state': 'Online' if authority.is_online() else 'Offline'}
            res.append(ca_data)
        return res

    @staticmethod
    def from_configparser(cfg):
        if not cfg.has_section('general'):
            err = 'Config File does not have a general section'
            raise Exception(err)

        if not cfg.has_option('general', 'enabled_authorities'):
            err = 'enabled_authorities not defined in general section'
            raise Exception(err)

        authorities = {}
        authorities_str = cfg.get('general', 'enabled_authorities')
        authority_names = authorities_str.split(',')
        for authority_name in authority_names:
            authority_section = "ca_{}".format(authority_name)
            if not cfg.has_section(authority_section):
                err = "Authority section for {} not found".format(authority_section)
                print(err)
                continue

            if cfg.has_option(authority_section, 'uuid'):
                authority_id = str(uuid.UUID(cfg.get(authority_section, 'uuid')))
            else:
                authority_id = str(uuid.uuid5(AUTHORITY_NAMESPACE, authority_name))

            authority = SSHCertAuthority.from_configparser(cfg, authority_section)
            authorities[authority_id] = authority

        return SSHCertAuthorityManager(authorities=authorities)


# vim: ts=4 expandtab
