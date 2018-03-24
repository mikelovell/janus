import time
import socket
from distutils.util import strtobool
from janus import util
from janus.certificate import SSH_CERT_TYPE_HOST, SSH_CERT_TYPE_USER

class BaseFilter(object):
    def __init__(self, **kwargs):
        pass

    def process(self, ctx, cert_request):
        pass

class DurationFilter(BaseFilter):
    name = "DurationFilter"
    cert_types = [SSH_CERT_TYPE_USER, SSH_CERT_TYPE_HOST]

    def __init__(self, **kwargs):
        max_duration = kwargs.get('max_duration', '0')
        max_duration = int(max_duration)
        self.max_duration = max_duration

    def process(self, ctx, cert_request):
        modified = False
        req_end = cert_request.valid_before
        if self.max_duration:
            cur_time = time.time()
            max_end = cur_time + self.max_duration
            if req_end > max_end:
                cert_request.valid_before = max_end
                modified = True
        return True, modified, False

class HostnameMatchesIP(BaseFilter):
    name = "HostnameMatchesIPFilter"
    cert_types = [SSH_CERT_TYPE_HOST]

    def __init__(self, **kwargs):
        self.allow_shell = strtobool(kwargs.get('allow_shell'))

    def process(self, ctx, cert_request):
        addr = ctx.req_addr

        if addr is None:
            if self.allow_shell:
                # TODO: Make sure the only time we don't have
                #       an address is when we're in a shell
                #       context.
                return True, False, False

            # We're not configured to allow shell
            # so not having a source address means
            # we can't do our job.
            return False, False, False

        for principal in cert_request.principals:
            try:
                dns_ip = socket.gethostbyname(principal)
                if dns_ip != addr:
                    return False, False, False
            except:
                # If we can't resolve DNS, we can't verify
                return False, False, False

        return True, False, False

class HostKeyMatches(BaseFilter):
    name = "HostKeyMatchesFilter"
    cert_types = [SSH_CERT_TYPE_HOST]
    def process(self, ctx, cert_request):
        if cert_request != SSH_CERT_TYPE_HOST:
            return True, False, False
        hostname = cert_request.principals[0]
        types = [cert_request.key.get_name()]

        keys = util.get_host_keys(hostname, types=types)
        key_strings = [k.get_base64() for k in keys]
        if cert_request.key.get_base64() in key_strings:
            return True, False, False

        return False, False, False

class UserOnlyPricipals(BaseFilter):
    name = "UserOnlyPrincipalFilter"
    cert_types = [SSH_CERT_TYPE_USER]
    def __init__(self, **kwargs):
        pass

    def process(self, ctx, cert_request):
        cert_request.pricipals = [ctx.username]
        return True, True, False

class AllowRootPrincipal(BaseFilter):
    name = "AllowRootPrincipalFilter"
    cert_types = [SSH_CERT_TYPE_USER]
    def __init__(self, **kwargs):
        allowed_users = kwargs.get('allowed_users', '')
        self.allowed_users = allowed_users.split(',')

    def process(self, ctx, cert_request):
        modified = False
        if 'root' in cert_request.principals:
            if ctx.username not in self.allowed_users:
                return False, False, False
        else:
            if ctx.username in self.allowed_users:
                cert_request.principals.append('root')
                modified = True
        return True, modified, False

class EnsureUsernamePrincipal(BaseFilter):
    name = "EnsureUsernamePrincipalFilter"
    cert_types = [SSH_CERT_TYPE_USER]
    def process(self, ctx, cert_request):
        modified = False
        if ctx.username not in cert_request.principals:
            cert_request.principals.append(ctx.username)
            modified = True
        return True, modified, False

