"""
NOTE: Requires python-ldap
"""
import ldap
import threading


class LDAPAuth(object):
    """
    Provides an `authenticate` method which takes an email address and
    password and authenticates with an LDAP server, returning the list of
    groups that the user belong to.
    """

    class AuthenticationError(Exception): pass

    lock = threading.Lock()
    connection = None

    def __init__(self, url, bind_dn='', bind_password='', base_dn='', group_dn=''):
        self.url = url
        self.bind_dn = bind_dn.encode('utf-8')
        self.bind_password = bind_password.encode('utf-8')
        self.base_dn = base_dn.encode('utf-8')
        self.group_dn = group_dn.encode('utf-8')

    def __call__(self, *args, **kwargs):
        return self.authenticate(*args, **kwargs)

    def authenticate(self, email, password):
        with self.lock:
            return self.authenticate_thread_unsafe(email, password)

    def authenticate_thread_unsafe(self, email, password):
        self.bind_connection()
        try:
            ldap_user = self.get_ldap_user_from_email(email)
            self.check_password_for_ldap_user(ldap_user, password)
        except self.AuthenticationError:
            return None
        return self.get_groups_for_ldap_user(ldap_user)

    def bind_connection(self):
        if self.connection is None:
            self.connection = ldap.initialize(self.url)
        # We rebind every time because a successful authentication will leave
        # us bound as the last user
        self.connection.simple_bind_s(
                self.bind_dn, self.bind_password)

    def get_ldap_user_from_email(self, email):
        search = (u"(mail=%s)" % email).encode('utf-8')
        results = self.connection.search_s(
                self.base_dn, ldap.SCOPE_SUBTREE, search)
        if len(results) == 1:
            return results[0][0]
        else:
            raise self.AuthenticationError()

    def check_password_for_ldap_user(self, ldap_user, password):
        try:
            self.connection.simple_bind_s(ldap_user, password.encode('utf-8'))
        except ldap.INVALID_CREDENTIALS:
            raise self.AuthenticationError()

    def get_groups_for_ldap_user(self, ldap_user):
        search = "(&(objectClass=groupOfNames)(member=%s))" % ldap_user
        results = self.connection.search_s(
                self.group_dn, ldap.SCOPE_SUBTREE, search)
        return [result[1]['cn'][0] for result in results]
