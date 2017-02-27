from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.message import Message
from paramiko.py3compat import StringIO
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import SSHException
from paramiko.transport import Transport

# Defined in PROTOCOL.certkeys
SSH_CERT_TYPE_USER = 1
SSH_CERT_TYPE_HOST = 2

VALID_CRITICAL_OPTIONS = {
    SSH_CERT_TYPE_USER: ["force-command",
                         "source-address"],
    SSH_CERT_TYPE_HOST: []
}

MAX_CERT_VALID_BEFORE = 2**64 - 1

def _parse_rsa_key(msg):
    # This method avoids having to keep track of how paramiko handles keys
    # or having to go into the cryptography.hazmat modules. It takes the
    # parts of the key from the certificate then puts them in a Message that
    # resembles a normally encoded keyh. That Message is then handed to the
    # key constructor which should be able to handle the parsing.
    key_msg = Message()
    key_msg.add_string('ssh-rsa')
    key_msg.add_mpint(msg.get_mpint())
    key_msg.add_mpint(msg.get_mpint())
    key_msg.rewind()
    return RSAKey(msg=key_msg)


def _parse_dsa_key(msg):
    # See comment for _parse_rsa_key
    key_msg = Message()
    key_msg.add_string('ssh-dss')
    key_msg.add_mpint(msg.get_mpint())
    key_msg.add_mpint(msg.get_mpint())
    key_msg.add_mpint(msg.get_mpint())
    key_msg.add_mpint(msg.get_mpint())
    key_msg.rewind()
    return DSSKey(msg=key_msg)


def _parse_ecdsa_key(msg):
    # See comment for _parse_rsa_key
    key_msg = Message()
    curve = msg.get_text()
    key_msg.add_string('ecdsa-sha2-{}'.format(curve))
    key_msg.add_string(curve)
    key_msg.add_string(msg.get_binary())
    key_msg.rewind()
    return ECDSAKey(msg=key_msg)


def _encode_rsa_key(msg, key, nonce):
    msg.add_string("ssh-rsa-cert-v01@openssh.com")
    msg.add_string(nonce)
    # The key in the certificate is the same as a normally encoded key except
    # for the key name at the beginning. i.e. after the ssh-rsa encoded str
    # which takes 11 bytes. This trick gets around changes to how paramiko
    # stores key variables in different releases.
    msg.add_bytes(key.asbytes()[11:])


def _encode_dsa_key(msg, key, nonce):
    msg.add_string("ssh-dss-cert-v01@openssh.com")
    msg.add_string(nonce)
    # See comment in _encode_rsa_key
    msg.add_bytes(key.asbytes()[11:])


def _encode_ecdsa_key(msg, key, nonce):
    curve_size = key.get_bits()
    cert_type = "ecdsa-sha2-nistp{}-cert-v01@openssh.com".format(curve_size)
    msg.add_string(cert_type)
    msg.add_string(nonce)
    # See comment in _encode_rsa_key
    msg.add_bytes(key.asbytes()[23:])


class SSHCertificate(object):
    """
    Representation of an OpenSSH Certificate. These are supported by OpenSSH
    5.4 and later. Documentation for the format of the certificates is
    documented in PROTOCOL.certkeys of the OpenSSH Source.
    """

    _key_parsers = {
        "ssh-rsa-cert-v01@openssh.com": _parse_rsa_key,
        "ssh-dss-cert-v01@openssh.com": _parse_dsa_key,
        "ecdsa-sha2-nistp256-cert-v01@openssh.com": _parse_ecdsa_key,
        "ecdsa-sha2-nistp384-cert-v01@openssh.com": _parse_ecdsa_key,
        "ecdsa-sha2-nistp521-cert-v01@openssh.com": _parse_ecdsa_key,
    }

    _key_encoders = {
        RSAKey: _encode_rsa_key,
        DSSKey: _encode_dsa_key,
        ECDSAKey: _encode_ecdsa_key,
    }

    _required_attributes = ['type', 'valid_after', 'valid_before', 'key_id']

    def __init__(self, msg=None, data=None, key=None):
        """
        Create a new instance of an SSHCertificate. If ``msg`` or ``data``
        is provided, then the certificate details will be filled out with the
        information from the ``msg`` or ``data``. If ``key` is provided along
        with ``msg or ``data``, then the public key in ``key`` must match the
        public key stored in the certificate. ``key`` may be specified on its
        own to start creation of a new certificate. Either ``key`` or one of
        ``msg`` or ``data`` must be specified.

        :param .Message msg:
            A paramiko.message.Message instance that contains the contents of
            the certificate
        :param str data:
            A string or byte sequence containing the contents of a cert
        :param .PKey key:
            An instance of a key, i.e. RSAKey, DSSKey, or ECDSAKey, to be
            used with an existing certificate or for creating a new one.

        :raises SSHException:
            If the key does not match the public key from the certificate or
            if neither an existing certificate or key were specified. An
            invalid certificate will also raise an exception.
        """
        self.nonce = None
        self.key = None
        self.serial = 0
        self.type = SSH_CERT_TYPE_USER
        self.key_id = None
        self.principals = []
        self.valid_after = None
        self.valid_before = None
        self.critical_options = {}
        self.extensions = {}
        self.reserved = None
        self.signature_key = None
        self.signature = None
        self._body_bytes = None
        self._bytes = None

        if (msg is None) and (data is not None):
            msg = Message(data)
        if msg is not None:
            self._from_message(msg)
            if not self.validate():
                err = "Certificate contents cannot be validated."
                raise SSHException(err)

        # Check to make sure that if a certificate and key were provided
        # that the provided key matches the public key in the cert.
        if key is not None and self.key and self.key != key:
            err = "Provided key does not match cert key"
            raise SSHException(err)

        if key is not None:
            self.key = key

        if not self.key:
            err = "Certificate or key must be provided"
            raise SSHException(err)


    def asbytes(self):
        """
        Returns a string of bytes representing this certificate. This can be
        passed to `__init__` to create a new SSHCertificate with the same
        data. This is in binary form. Displaying or writing to file should
        base64.b64encode the data first.
        """
        return self._bytes


    def __str__(self):
        return self.asbytes()


    def get_name(self):
        """
        See paramiko.pkey.PKey. Varies by key type in the certificate.
        """
        #if type(self.key) == RSAKey:
        #    return "ssh-rsa-cert-v01@openssh.com"
        #elif type(self.key) == DSSKey:
        #    return "ssh-dss-cert-v01@openssh.com"
        #elif type(self.key) == ECDSAKey:
        #    return "{}-v01@openssh.com".format(self.key.get_name())
        return "{}-cert-v01@openssh.com".format(self.key.get_name())


    def get_bits(self):
        """
        See paramiko.pkey.PKey
        """
        return self.key.get_bits()


    def can_sign(self):
        """
        See paramiko.pkey.PKey
        """
        return self.key.can_sign()


    def get_fingerprint(self):
        """
        See paramiko.pkey.PKey
        """
        return self.key.get_fingerprint()


    def get_base64(self):
        """
        See paramiko.pkey.PKey
        """
        return self.key.get_base64()


    def sign_ssh_data(self, data):
        """
        See paramiko.pkey.PKey
        """
        return self.key.sign_ssh_data(data)


    def verify_ssh_sig(self, data, msg):
        """
        See paramiko.pkey.PKey
        """
        return self.key.verify_ssh_sig(data, msg)


    def sign(self, ca_key, nonce):
        """
        Sign this certificate with the specified ``ca_key``. The ``ca_key``
        must include a private key and be able to sign data. The ``nonce``
        must be provided. Usually this would be something random, i.e. from
        os.urandom(32), but can any string. Testing re-used the nonce from
        the existing certificate to verify that re-signing results in the
        same certificate

        :param .PKey ca_key:
            The key to use as a CA for signing the certificate
        :param str nonce:
            A string to random data to use in the signing of the certificate

        :raises SSHException:
            If the ca_key cannot be used for signing.
        """
        if not ca_key.can_sign():
            err = "Provided key cannot be used for signing"
            raise SSHException(err)

        new_bytes = self.generate_body(ca_key, nonce)
        sig = ca_key.sign_ssh_data(new_bytes)
        # If the key used to sign the data was a paramiko.Agent.AgentKey, the
        # results are a string/binary sequence. If a paramiko.pkey.PKey was
        # used, then the result is a Message. Convert to a string as needed.
        if type(sig) == Message:
            sig = sig.asbytes()

        msg = Message()
        msg.add_bytes(new_bytes)
        msg.add_string(sig)

        # Set new values on self after the signing process has been completed
        # and the new certificate is ready.
        self.nonce = nonce
        self.signature = sig
        self.signature_key = ca_key.asbytes()
        self._body_bytes = new_bytes
        self._bytes = msg.asbytes()


    def validate(self):
        """
        Verify that the contents of the certificate have been signed by the
        signing key in the certificate. This only does the cryptographic
        verification. Validation that the signing key is an accepted CA key
        or verifying other information such as timestamps or principals is
        not done here and is the responsibility of the application using the
        certificate.

        :return bool:
            True if the certificate data was signed by the CA in the cert.
            False if not.
        """
        if self.signature is None or self.signature_key is None:
            return False

        # The signature_key is just a string containing the binary data of
        # the key. This will create a message of that data, determine the key
        # type from the first field, and then pass the message to the
        # appropriate key class.
        ca_key_msg = Message(self.signature_key)
        ca_key_type = ca_key_msg.get_text()
        ca_key_msg.rewind()
        ca_key_class = Transport._key_info.get(ca_key_type)
        if ca_key_class == None:
            err = "Unknown signature key type"
            raise SSHException(err)
        ca_key = ca_key_class(msg=ca_key_msg)

        # Create the certificate body if it hasn't been done already.
        if self._body_bytes is None:
            self._body_bytes = self.generate_body(ca_key, self.nonce)

        return ca_key.verify_ssh_sig(self._body_bytes, Message(self.signature))


    def _from_message(self, msg):
        """
        Internal fuction to parse the contents of a certificate. There are
        several pieces of information to be parsed specificed by
        PROTOCOL.certkeys in the OpenSSH source code.

        string cert_key_type (i.e. "ssh-rsa-cert-v01@openssh.com")
        string nonce
        various public key data : Fields and types dependent on key type
        uint64 serial
        uint32 type
        string key_id
        string principals : Message containing a list of principals
        uint64 valid_after
        uint64 valid_before
        string critical_options : Message containing various critical options
        string extensions : Mesage containing optional extensions
        string reserved
        string signature_key
        string signature

        :param .Message msg:
            An instance of a paramiko.message.Message containing the
            certificate data.
        """
        cert_key_type = msg.get_text()
        self.nonce = msg.get_binary()

        # Use the _key_parsers dictionary to look up the appropriate key
        # parser to read the key. Then dispatch to that function to do the
        # actual reading of the key data.
        key_parser = self._key_parsers.get(cert_key_type)
        if key_parser is None:
            err = "Unknown cert key type {}".format(cert_key_type)
            raise SSHException(err)
        self.key = key_parser(msg)

        self.serial = msg.get_int64()
        self.type = msg.get_int()
        self.key_id = msg.get_text()

        principals_msg = Message(msg.get_binary())
        while principals_msg.get_remainder():
            self.principals.append(principals_msg.get_text())

        self.valid_after = msg.get_int64()
        self.valid_before = msg.get_int64()

        copts_msg = Message(msg.get_binary())
        while copts_msg.get_remainder():
            opt = copts_msg.get_text()
            val_msg = Message(copts_msg.get_binary())
            val = val_msg.get_text()
            self.set_critical_option(opt, val)

        ext_msg = Message(msg.get_binary())
        while ext_msg.get_remainder():
            ext = ext_msg.get_text()
            val = ext_msg.get_binary()
            self.extensions[ext] = val

        self.reserved = msg.get_string()
        self.signature_key = msg.get_binary()
        self._body_bytes = msg.get_so_far()
        self.signature = msg.get_binary()
        self._bytes = msg.get_so_far()


    def has_required_attrs(self):
        for attrib in self._required_attributes:
            if getattr(self, attrib) is None:
                return False
        return True

    def generate_body(self, key, nonce):
        """
        Create a sequence of bytes representing the certificate except for
        the signature. This is used duing the signing process to generate
        the body of the certificate for the CA key to sign. ``key`` is an
        instance of a paramiko.pkey.PKey and is only used for recording the
        public part in body of the certificate. ``nonce`` is a string to use
        in the body. This fuction does not change any saved state of the
        existing certificate. That is done in `sign`

        The attributes in _required_attributes must be defined before the
        certificate can be properly created and signed.

        :param .PKey key:
            The key that will be used for signing.
        :param str nonce:
            A random nonce

        :raises SSHException:
            If an unknown key is specified for the certificate or if an
            invalid critical option for the given key type has been used.
            Only known critical options are allowed per PROTOCOL.certkeys.
            An exceptions is also thrown if a required attribute is missing.
        """
        for attrib in self._required_attributes:
            if getattr(self, attrib) is None:
                err = "Required Attribute {} not set".format(attrib)
                raise SSHException(err)

        msg = Message()

        # Use the _key_encoders dictionary to determine a function to use to
        # add the key to the beginning of the certificate body. Since parts
        # are before and after the nonce, include the nonce in the call.
        key_encoder = self._key_encoders.get(type(self.key))
        if not key_encoder:
            err = "Unknown key type"
            raise SSHException(err)

        key_encoder(msg, self.key, nonce)

        msg.add_int64(self.serial)
        msg.add_int(self.type)
        msg.add_string(self.key_id)

        if len(self.principals) == 0:
            msg.add_int(0)
        else:
            princ_msg = Message()
            for princ in self.principals:
                princ_msg.add_string(princ)
            msg.add_string(princ_msg.asbytes())

        msg.add_int64(self.valid_after)
        msg.add_int64(self.valid_before)

        if len(self.critical_options) == 0:
            msg.add_int(0)
        else:
            # Critical Options have to be added to the certificate in
            # lexical order.
            copts_msg = Message()
            opts = sorted(self.critical_options.keys())
            for opt in opts:
                if opt not in VALID_CRITICAL_OPTIONS[self.type]:
                    err = "Invalid critical option {}".format(opt)
                    raise SSHException(err)
                copts_msg.add_string(opt)
                val_msg = Message()
                val_msg.add_string(self.critical_options[opt])
                copts_msg.add_string(val_msg.asbytes())
            msg.add_string(copts_msg.asbytes())

        if len(self.extensions) == 0:
            msg.add_int(0)
        else:
            # Extensions also have to be added to the certificate in
            # lexical order.
            ext_msg = Message()
            exts = sorted(self.extensions.keys())
            for ext in exts:
                ext_msg.add_string(ext)
                ext_msg.add_string(self.extensions[ext])
            msg.add_string(ext_msg.asbytes())

        msg.add_string('')
        msg.add_string(key.asbytes())

        return msg.asbytes()


    def set_critical_option(self, option, value):
        """
        Set the value of a critical option on the certificate. Only known
        critial options are allowed to be in the certificate. This fuction
        can be used to validate the option while setting it in the
        critical_options dictionary. No critical options are currently known
        for SSH_CERT_TYPE_HOST. Only 'force-command' and 'source-address' are
        known for SSH_CERT_TYPE_USER.

        :param str option:
            Name of the critical option to set.
        :param str value:
            Value to set the option to

        :raises SSHException:
            An exception is raised if an unknown option is specified for the
            type of certificate being used.
        """
        if option not in VALID_CRITICAL_OPTIONS[self.type]:
            err = "Invalid option {} for type {}".format(option, self.type)
            raise SSHException(err)
        self.critical_options[option] = value


# Several test certificates generated by ssh-keygen. The first was generated
# using the following command and fills in every potential field with data.
#
# ssh-keygen -s rsa-ca -I rsa-test-key -n test1,test2 \
# -V 20100101123000:20110101123000 -z 1234 -O no-x11-forwarding \
# -O force-command=/bin/bash rsa-test-key.pub
#
# RSA Certificate signed by an RSA Key
TEST_RSA_KEY_RSA_CA = "AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAguwMuSleH1J3mRYJqfpPZHKuZJ+lFoKiKMdLG8OnOdmgAAAADAQABAAAAgQC+Z52sMz5unflEMhuCTSN5eEYvvxRRHcJ+MoqWXGGLyruibDIFQ47Qpo376hIK6rF0fU9pAgHXAT9THZ0QjP6qx+obVjAEeU5YcdwymV2tlKaZsL1BDCIgNdekQB4WhAJK+yKds9uDTfZ8dDImESQtrOkDGgSDPrhlHOQ+05ZRvQAAAAAAAATSAAAAAQAAAAxyc2EtdGVzdC1rZXkAAAASAAAABXRlc3QxAAAABXRlc3QyAAAAAEs+TTgAAAAATR+AuAAAACIAAAANZm9yY2UtY29tbWFuZAAAAA0AAAAJL2Jpbi9iYXNoAAAAZQAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAJcAAAAHc3NoLXJzYQAAAAMBAAEAAACBAMZ4gX9QfuYpI+g3GXMwu4j7rDD6QShPqBLPrdztUS1EycKdCIPOOlSU5PsMNsQ4Bvyyk8aGl6SLo1/pLyQAyZ/DyTNPUG2JgkJwKypftzAYEAUtD7xZ47B7mqCgAxRn3Ff1dN5yoiLsTvY6WkqgOGEfOJpsLZabjwM3MDcYbXoxAAAAjwAAAAdzc2gtcnNhAAAAgDxfl9aR2K17aCN2DJb4ze6e4b3n9+4xqahPHCP48aC7KyNhEb2tnxvIs7zebLNFGv/WnIYYzBHFwAsnFU/j78AEgB1qeed7We/Epfp328qv7bTFTXE4WGGlwd/4rSVKK4JepeH0BS9iJraATiaBDr8/o3+QT21FuXscSBjv8efd"
# DSA Certificate signed by an RSA Key
TEST_DSA_KEY_RSA_CA = "AAAAHHNzaC1kc3MtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgksXC7PMXrDOFB9FTaKUuGKfHW4u8wX+UIEdfflLgJVoAAACBAMNvdvtUfTFXlJFYxnbcx5kME3W7fc2Z8W6kJlZ5PwBzzigODcBGOmEEEoRj+nyIMx/eGXY3BDRWKd77wqqRBMKSWQwqWXBBHU0RX0IKGQ4S1kyaUdYB/61SLR/a2n8G9/2iwo5JmgAyJ6uIys77fJWDtT0sxfGroxrUhtFvbkAFAAAAFQDc44GjvE1V4oKmNT/GI8Sa5EZqxQAAAIEAmlSk6lJHfowopGWxo+I17NY4EwsOdYA/UnvICK6iJlN6ByxlxqKSguAakCTM339nZVt44cRiJL5RgWx5sPnlGoTQo3fdCoy1p+MHJvkboVTXPf6/UcpNE9winWXJMlpFlf5ex5U2YfMm6dQhxFYBkkxYY+tiEBp5Ffm3/Ol0qiEAAACAeJdaPAZ5TdUlYmdZcCGjDzE/8ohv8VzE7XkjB6zSByWu7La0qCEEz9EMPK2AXj8PvMKkWPFH962lLpNK+98jKwVCaMG9tV0maQ7H6FOZDwErDY0FQxsGzJf3mdEELkM02Xpyv4Z83ryxjzL9hrwuSZi37wrqUEHIUBSMEim0pjYAAAAAAAAAAAAAAAEAAAAMZHNhLXRlc3Qta2V5AAAACQAAAAV0ZXN0MQAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAlwAAAAdzc2gtcnNhAAAAAwEAAQAAAIEAxniBf1B+5ikj6DcZczC7iPusMPpBKE+oEs+t3O1RLUTJwp0Ig846VJTk+ww2xDgG/LKTxoaXpIujX+kvJADJn8PJM09QbYmCQnArKl+3MBgQBS0PvFnjsHuaoKADFGfcV/V03nKiIuxO9jpaSqA4YR84mmwtlpuPAzcwNxhtejEAAACPAAAAB3NzaC1yc2EAAACAl5ctp2ukhI8w1FbRUv39F24zWKwDTQRjenzFmWVCggGCCkTVnSRug6p8HqqoXQMqj7Y0bswIf8jPf3xyyw9lEcYw92iU/2SCXqIbJzFjrs85YlUybRrRaFJvdawva0CRTkNXJzZkhbFuIB2P7dgGayMWr2rK0ggfpgGq47385zQ="
# ECDSA 256 Certificate signed by an RSA Key
TEST_ECDSA_KEY_RSA_CA = "AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgKXpUSA2JXyp/MjsDh2GKEDACWrXqGW02MbTdoQf3RsMAAAAIbmlzdHAyNTYAAABBBC+NpigNnQRrN+zQho8hzFPr8ZLzuuLLio1gIr2bDsv/r511BqiPMnOaqSx1MxJndYUYiEYnHX3cB/bl4cSVGWIAAAAAAAAAAAAAAAEAAAAOZWNkc2EtdGVzdC1rZXkAAAAJAAAABXRlc3QxAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAACXAAAAB3NzaC1yc2EAAAADAQABAAAAgQDGeIF/UH7mKSPoNxlzMLuI+6ww+kEoT6gSz63c7VEtRMnCnQiDzjpUlOT7DDbEOAb8spPGhpeki6Nf6S8kAMmfw8kzT1BtiYJCcCsqX7cwGBAFLQ+8WeOwe5qgoAMUZ9xX9XTecqIi7E72OlpKoDhhHziabC2Wm48DNzA3GG16MQAAAI8AAAAHc3NoLXJzYQAAAIABUNuWpkpz22Et3J+Czoq9rqv3mj30l6YoV8uWfIM48UuacpujyR6BfzXd9mVHyEj+GDv3sBbODp3Az9qoxEtV4URJADgPieXZWXoKpOlD177AkPN+9nKmUQN446DZz521/DwxCcw4mvr8Gz8Qo6VQxOKlKN2qRITrR8vuyi4v5Q=="
# ECDSA 384 Certificate signed by an RSA Key
TEST_ECDSA384_KEY_RSA_CA = "AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgm9L1g1vaL9SJAoAP/KIP3xd+mKs6SHN03vRqe+9vnQ0AAAAIbmlzdHAzODQAAABhBLj0A1O9/AZTGONlNBeCX1vCA5FhQQtfqEaFjlDMH59k/4dVVraeuCYT6T2CCT+iMn7MbQvTN2b1gOCgmHizj0ndNqyWYWQCI0RXo3JXvoUXauZfSb4x3secohIBDawarQAAAAAAAAAAAAAAAQAAABFlY2RzYTM4NC10ZXN0LWtleQAAAAkAAAAFdGVzdDEAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAJcAAAAHc3NoLXJzYQAAAAMBAAEAAACBAMZ4gX9QfuYpI+g3GXMwu4j7rDD6QShPqBLPrdztUS1EycKdCIPOOlSU5PsMNsQ4Bvyyk8aGl6SLo1/pLyQAyZ/DyTNPUG2JgkJwKypftzAYEAUtD7xZ47B7mqCgAxRn3Ff1dN5yoiLsTvY6WkqgOGEfOJpsLZabjwM3MDcYbXoxAAAAjwAAAAdzc2gtcnNhAAAAgDWRpjEpL9GlPG5bmrz/u5DsFkP1gQSYz60g8hHkHas8qlsiCzhklTEOYAiWrWA3lTyBr6NJLk7e1opouacAWZs1wD/qAnVDlA+XzKXMc0SZExU7q4FWMgnMKg2PtG3is1+RVkQIEwr2xYmT/8nMIP5rQF5LNVKGbZLwqjN5wjLC"
# ECDSA 521 Certificate signed by an RSA Key
TEST_ECDSA521_KEY_RSA_CA = "AAAAKGVjZHNhLXNoYTItbmlzdHA1MjEtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgIUugVPlS40/3HcGAniYkoCW8kGa+vIkdpXjsPZUbvqEAAAAIbmlzdHA1MjEAAACFBAHh4aQXJ0s5iN6QXD7QJlAASiDCWW1Gy8j/RS6E3a7DuYSVpEDKHg6aAef5iL9NebV5GogVyFCfNEMHKsQaWp1FKwHhT8V+GzVAy9ZlZsG7cUYVzjXvV6sDvq0kgiq9V6ThzR43/aBWN2kTuPDtZtCq7r0+FH83LdJE8lgv7IRuTSV/HQAAAAAAAAAAAAAAAQAAABFlY2RzYTUyMS10ZXN0LWtleQAAAAkAAAAFdGVzdDEAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAJcAAAAHc3NoLXJzYQAAAAMBAAEAAACBAMZ4gX9QfuYpI+g3GXMwu4j7rDD6QShPqBLPrdztUS1EycKdCIPOOlSU5PsMNsQ4Bvyyk8aGl6SLo1/pLyQAyZ/DyTNPUG2JgkJwKypftzAYEAUtD7xZ47B7mqCgAxRn3Ff1dN5yoiLsTvY6WkqgOGEfOJpsLZabjwM3MDcYbXoxAAAAjwAAAAdzc2gtcnNhAAAAgAKBUnFnL+R4r2Q3z3Y1EiSxeK74o5sq6x/vnIhaFihlAob8/NxVwb/4CCiTBhi/TRsylCo155fTa3OcfAK7ITHB901oumvuRJFqOwFeE7/FiUOqdTG6PnhhU4Z3SvczHswJvmntZ0mlw+knqopE4PT+ompwfT/ZC5XzIcG6fpEG"
# RSA Certificate signed by an DSA Key
TEST_RSA_KEY_DSA_CA = "AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgM+p0fP+rKu5nPQhqB8wv8V09KDvSbAJ2VvH89OB/PI0AAAADAQABAAAAgQC+Z52sMz5unflEMhuCTSN5eEYvvxRRHcJ+MoqWXGGLyruibDIFQ47Qpo376hIK6rF0fU9pAgHXAT9THZ0QjP6qx+obVjAEeU5YcdwymV2tlKaZsL1BDCIgNdekQB4WhAJK+yKds9uDTfZ8dDImESQtrOkDGgSDPrhlHOQ+05ZRvQAAAAAAAATSAAAAAQAAAAxyc2EtdGVzdC1rZXkAAAASAAAABXRlc3QxAAAABXRlc3QyAAAAAEs+TTgAAAAATR+AuAAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAGxAAAAB3NzaC1kc3MAAACBAKF6C01ZBAxnhNA+25rbQ51piqi71WMiKZiNrbc5mpInFgpP/p0l2VmpAZ2JQuOjqQnanQ+YJMAz5CPScx7qs5ASxQLubYyjGWR/d6gztjXtfLcQEAFzuIeri58PSJ/Gy6Yg7NN5tAFvCeBW5rvvTB4crpH2TBIebyqUmaSLZid9AAAAFQDUMw6joaxn7qwFJatQgD4ONj92ywAAAIBj3jBYG+JVszNpGmzilsojyyN52yfOgKiSQz5EzwsEbWgK1rT7q+nQATuWiypA17g6UH/l1kChUF0fqnVq20YPIJDIRPI6V+fzS2Y2DWnn0A+9wNpqDnYVnmAgw365yQyR9bfcBAU2WWC2vzmdgVIM6i6WWdFc2EB6cRKHFJeE1gAAAIBMd8F3yUQ08oO+xl1dpM4/dnWFSy98MuwgVqXXn0P2839SbhXbsFNeeES//+hWzAM4Abv/6chvfPBIg52Gkvl9bRMCNiXgpVTevPSYC4XNkUc4Y0xAn+ntxjME+biadERl5AyAhni1ecqBkPs9cVW/gu78SdWNcP7pknQLPgASmQAAADcAAAAHc3NoLWRzcwAAACjJ/Nl3H8sHOJjXvYYwkdyXWJ64BCMMHPwNrTLkkxjz4bij7uk2e9gS"
# RSA Certificate signed by an ECDSA Key
TEST_RSA_KEY_ECDSA_CA = "AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgADSw9RgdySvVxdt25CSxRnyBQl5zYLdBCX+/dtsihd0AAAADAQABAAAAgQC+Z52sMz5unflEMhuCTSN5eEYvvxRRHcJ+MoqWXGGLyruibDIFQ47Qpo376hIK6rF0fU9pAgHXAT9THZ0QjP6qx+obVjAEeU5YcdwymV2tlKaZsL1BDCIgNdekQB4WhAJK+yKds9uDTfZ8dDImESQtrOkDGgSDPrhlHOQ+05ZRvQAAAAAAAATSAAAAAQAAAAxyc2EtdGVzdC1rZXkAAAASAAAABXRlc3QxAAAABXRlc3QyAAAAAEs+TTgAAAAATR+AuAAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE+BMK6rRje7bC52qNPVQlyiFxe45UqKT4Exf2SVRD7F863jn3N9bdA7ytSHwJH7PGmUdIvvMMaq9mfxeKFtu/IAAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIQChE9tPhg7KGmgrT57BlexNSCHOUxhTl5vAIfTCNaJg2gAAACA4/3vyWoZq76Wf1qQ/bl+mOXZ1DfDEvcpd3fI40b/IqQ=="

# RSA Key used as a CA for several of the test certs.
TEST_RSA_CA = """\
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDGeIF/UH7mKSPoNxlzMLuI+6ww+kEoT6gSz63c7VEtRMnCnQiD
zjpUlOT7DDbEOAb8spPGhpeki6Nf6S8kAMmfw8kzT1BtiYJCcCsqX7cwGBAFLQ+8
WeOwe5qgoAMUZ9xX9XTecqIi7E72OlpKoDhhHziabC2Wm48DNzA3GG16MQIDAQAB
AoGBAITJy5qq+Lx1ehi8BMMVL+QOvr5mMYIPCZzMZr8R6OYox/T1q+TD7jL5C9sL
6PiPo90efdCt7HejFcPt+CRWgo68gxno8xJU+OKlqn/I2DchR2KZ9VmXBXj/xO01
Rv7b7AiH+QUAlFzJvQWXTHmqtaeO6qkcbWIZdbG5cmIcKxihAkEA49onIUc4/3H2
Io78N6YI4cSJXJZ1txP1Xrg9bjmv5VSrCWaRs/JoVmm8ak0J/W+eJ2m3rNuTO5E8
9E+A5SbycwJBAN79KYjl+Bm3CyfXR3+wYHdFzzmQd+7PE69edVm+QJNH5QpQFKQC
Rm/RnOY5tjOgQOjZWQ+eP056OsDGfQoko8sCQEIPiNLMLIlbSCqC3DtiJycV7WFr
uhtnbPeWYTEpBoduAdzK4SmT+Y48P8VuKpxRFUCGFRvH2asmk86dklhd72MCQD+Z
bTNChBSxhFkEqbvdjmX2XzhH4C0YmsC17DqAbOKU6tqaJIjyrSxPWLTBWRo4ZssC
0sgFloDHk+JPunIeKSkCQQCBGthACKX/Ducv0HbmyOldjAC0uQczfVVDQwJlOfew
n2G+Gc9S7F568QXcfRv+yPWPGrYBXwwqLb5O1XESPTYe
-----END RSA PRIVATE KEY-----
"""

def test_parse_rsa_key_rsa_ca():
    msg = Message(base64.b64decode(TEST_RSA_KEY_RSA_CA))
    crt = SSHCertificate(msg=msg)
    assert type(crt.key) == RSAKey
    assert crt.serial == 1234
    assert crt.type == SSH_CERT_TYPE_USER
    assert crt.key_id == "rsa-test-key"
    assert crt.principals == ['test1', 'test2']
    assert crt.valid_after == 1262374200
    assert crt.valid_before == 1293910200
    assert len(crt.critical_options) == 1
    assert crt.critical_options['force-command'] == '/bin/bash'
    assert len(crt.extensions) == 4
    assert 'permit-agent-forwarding' in crt.extensions.keys()
    assert 'permit-port-forwarding' in crt.extensions.keys()
    assert 'permit-pty' in crt.extensions.keys()
    assert 'permit-user-rc' in crt.extensions.keys()
    assert crt.validate()

def test_parse_dsa_key_rsa_ca():
    msg = Message(base64.b64decode(TEST_DSA_KEY_RSA_CA))
    crt = SSHCertificate(msg=msg)
    assert type(crt.key) == DSSKey
    assert crt.validate()

def test_parse_ecdsa_key_rsa_ca():
    msg = Message(base64.b64decode(TEST_ECDSA_KEY_RSA_CA))
    crt = SSHCertificate(msg=msg)
    assert type(crt.key) == ECDSAKey
    assert crt.validate()

def test_parse_ecdsa384_key_rsa_ca():
    msg = Message(base64.b64decode(TEST_ECDSA384_KEY_RSA_CA))
    crt = SSHCertificate(msg=msg)
    assert type(crt.key) == ECDSAKey
    assert crt.validate()

def test_parse_ecdsa521_key_rsa_ca():
    msg = Message(base64.b64decode(TEST_ECDSA521_KEY_RSA_CA))
    crt = SSHCertificate(msg=msg)
    assert type(crt.key) == ECDSAKey
    assert crt.validate()

def test_parse_rsa_key_dsa_ca():
    msg = Message(base64.b64decode(TEST_RSA_KEY_DSA_CA))
    crt = SSHCertificate(msg=msg)
    assert type(crt.key) == RSAKey
    assert crt.validate()

def test_parse_rsa_key_ecdsa_ca():
    msg = Message(base64.b64decode(TEST_RSA_KEY_ECDSA_CA))
    crt = SSHCertificate(msg=msg)
    assert type(crt.key) == RSAKey
    assert crt.validate()

def test_sign():
    """
    Round trip a certificate through the parser and signer. It should result
    in the same sequence of bytes after the signing.
    """
    ca_buf = StringIO(TEST_RSA_CA)
    ca_key = RSAKey.from_private_key(ca_buf)

    crt_data = base64.b64decode(TEST_RSA_KEY_RSA_CA)
    crt = SSHCertificate(data=crt_data)
    assert crt.signature_key == ca_key.asbytes()
    crt._bytes = None
    assert crt._bytes != crt_data
    crt.sign(ca_key, crt.nonce)
    assert crt._bytes == crt_data

def test_sign_ecdsa_key():
    """
    Round trip a certificate through the parser and signer. It should result
    in the same sequence of bytes after the signing.
    """
    ca_buf = StringIO(TEST_RSA_CA)
    ca_key = RSAKey.from_private_key(ca_buf)

    crt_data = base64.b64decode(TEST_ECDSA_KEY_RSA_CA)
    crt = SSHCertificate(data=crt_data)
    assert crt.signature_key == ca_key.asbytes()
    crt._bytes = None
    assert crt._bytes != crt_data
    crt.sign(ca_key, crt.nonce)
    assert crt._bytes == crt_data

def test_gen_and_sign():
    ca_buf = StringIO(TEST_RSA_CA)
    ca_key = RSAKey.from_private_key(ca_buf)

    cert_file = open('/home/mike/.ssh/id_rsa', 'r')
    cert_key = RSAKey.from_private_key(cert_file)
    crt = SSHCertificate(key=cert_key)
    crt.type = SSH_CERT_TYPE_USER
    crt.key_id = 'testcert'
    crt.valid_after = 0
    crt.valid_before = 2**64 - 1
    crt.principals.append('mike')
    crt.extensions['permit-X11-forwarding'] = ''
    crt.extensions['permit-agent-forwarding'] = ''
    crt.extensions['permit-port-forwarding'] = ''
    crt.extensions['permit-pty'] = ''
    crt.extensions['permit-user-rc'] = ''
    crt.sign(ca_key, 'randomdata')
    return base64.b64encode(crt.asbytes())

if __name__ == "__main__":
    import base64
    test_parse_rsa_key_rsa_ca()
    test_parse_dsa_key_rsa_ca()
    test_parse_ecdsa_key_rsa_ca()
    #test_parse_ecdsa384_key_rsa_ca()
    #test_parse_ecdsa521_key_rsa_ca()
    test_parse_rsa_key_dsa_ca()
    test_parse_rsa_key_ecdsa_ca()
    test_sign()
    test_sign_ecdsa_key()
    #print test_gen_and_sign()

# vim: ts=4 expandtab
