#!/usr/bin/env python
import logging
import os

from sftp_server.sftp import SFTPServer
from sftp_server.permissions_manager import PermissionsManager
from sftp_server.ldap_auth import LDAPAuth
from sftp_server.permissions_file import read_permissions_file


SSH_PORT = 2222

development_root = os.path.join(os.path.dirname(__file__), 'tmp')
FILE_ROOT = os.path.realpath(os.environ.get(
        'FILESERVER_ROOT', development_root))
# Note, you can generate a new host key like this:
# ssh-keygen -t rsa -N '' -f host_key
HOST_KEY = os.path.join(os.path.dirname(__file__), 'config/host_key')
PERMISSIONS_FILE = os.path.join(os.path.dirname(__file__), 'config/permissions.ini')

AUTH_LDAP_SERVER_URI = "ldap://ldap-server.example.com"
AUTH_LDAP_BIND_DN = "cn=Directory Manager"
AUTH_LDAP_BIND_PASSWORD = "<PASSWORD>"
LDAP_ROOT_DN='dc=timetric,dc=com'
LDAP_GROUP_ROOT_DN='ou=timetric,ou=groups,%s' % LDAP_ROOT_DN
REQUIRED_GROUP = 'staff'


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    permissions = read_permissions_file(PERMISSIONS_FILE)
    ldap_auth = LDAPAuth(AUTH_LDAP_SERVER_URI,
        bind_dn=AUTH_LDAP_BIND_DN,
        bind_password=AUTH_LDAP_BIND_PASSWORD,
        base_dn=LDAP_ROOT_DN,
        group_dn=LDAP_GROUP_ROOT_DN)
    manager = PermissionsManager(permissions,
            required_group=REQUIRED_GROUP,
            authenticate=ldap_auth)
    server = SFTPServer(FILE_ROOT, HOST_KEY, get_user=manager.get_user)
    server.serve_forever('0.0.0.0', SSH_PORT)
