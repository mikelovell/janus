import time

class BaseFilter(object):
    def __init__(self, **kwargs):
        pass

    def process(self, ctx, cert_request):
        pass

class DurationFilter(BaseFilter):
    name = "DurationFilter"
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

class UserOnlyPricipals(BaseFilter):
    name = "UserOnlyPrincipalFilter"
    def __init__(self, **kwargs):
        pass

    def process(self, ctx, cert_request):
        cert_request.pricipals = [ctx['username']]
        return True, True, False

class AllowRootPrincipal(BaseFilter):
    name = "AllowRootPrincipalFilter"
    def __init__(self, **kwargs):
        allowed_users = kwargs.get('allowed_users', '')
        self.allowed_users = allowed_users.split(',')

    def process(self, ctx, cert_request):
        modified = False
        if 'root' in cert_request.principals:
            if ctx['username'] not in self.allowed_users:
                return False, False, False
        else:
            if ctx['username'] in self.allowed_users:
                cert_request.principals.append('root')
                modified = True
        return True, modified, False

class EnsureUsernamePrincipal(BaseFilter):
    name = "EnsureUsernamePrincipalFilter"
    def process(self, ctx, cert_request):
        modified = False
        if ctx['username'] not in cert_request.principals:
            cert_request.principals.append(ctx['username'])
            modified = True
        return True, modified, False

