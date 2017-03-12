=====
Janus
=====

tl;dr
-----

Janus can help make requesting SSH Certificates easier for Users while still
allowing for administrators to enforce security policy.

Introduction
------------

Janus is an application that is built to help make use of SSH Certificates
easier and more secure. SSH Certificates were introduced in OpenSSH 5.4 and
provide a way reduce some of the operational expense of maintaining and
distributing SSH Public Keys. They allow for specifying signing one public key,
along with additional information, with a Certificate Authority key. Users and
Hosts can then verify another User or Hosts but checking the validity of that
signed key and compare the Certificate Authority against their own list of
trusted authorities. There are several tutorials on using SSH Certificates
themselves. DigitalOcean has a good one at
https://www.digitalocean.com/community/tutorials/how-to-create-an-ssh-ca-to-validate-hosts-and-clients-with-ubuntu.

SSH Certificates by themselves provide many advantages such as not having to
distribute individual User authorized_keys to many systems. SSH Certificates
provide the potential for much more through the use of the additional
information stored in the certificates, such as the validity time range or
constraints on how the certificate is used. Limiting use of certificates to a
short period of time with the OpenSSH tools is not practical since it would
involve someone with access to the private key of the Certificate Authority to
sign new certificates all the time. A tool that lets Users request certificates
and that enforces security policy reduces the overhead and encourages regular
rotation of keys. This is the role that Janus is trying to fill. Currently,
Janus has support for creating a new SSH keypair, requesting a new certificate
using the public key, and then adding both the private key and certificate to an
ssh-agent.

Architecture
------------

Janus is configured with one or more Certificate Authorities. Each Authority
contains a Private Key, a Datastore, and a set of Policy Filters. The Private
Key is just a normal SSH keypair with the private key being specified as a file
on disk or through a connection to an ssh-agent. The Datastore is how the
Authority keeps track of various bits of information such as which certificates
have been issued and what the next serial number is. Finally, the Policy Filters
provide a way to constrain the attributes of a certificate. These Policy Filters
are processed in order and can outright reject a request, modify the request, or
simply let the request proceed.

