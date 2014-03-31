class PermissionsManager(object):
    """
    Manages permissions on a directory tree.

    An `authenticate` method must be supplied which should take a username and
    password and return a list of groups to which they belong (or None if the
    credentials are invalid)

    The permissions are specified via a dict which maps paths to sets of groups
    which have write access on that path. (Write access on a path implies write
    access on all its children.)

    All valid users have read access to all files.

    If `required_group` is set then users must belong to this group to be
    considered valid.

    The class provides a `get_user` method which can be passed to an `SFTPServer`
    instance to handle authentication and permissions.
    """

    def __init__(self, permissions, required_group=None, authenticate=None):
        self.permissions = permissions
        self.required_group = required_group
        if authenticate:
            self.authenticate = authenticate

    def authenticate(self, username, password):
        # Should return the list of groups the user belongs to if user
        # authenticates correctly, and None otherwise
        raise NotImplementedError()

    def get_user(self, username, password):
        groups = self.authenticate(username, password)
        if groups is None:
            return None
        groups = set(groups)
        if (self.required_group is not None
                and self.required_group not in groups):
            return None
        return User(self, groups, username)

    def has_read_access(self, groups, path):
        # All users have read access everywhere
        return True

    def has_write_access(self, groups, path):
        # Check every element of the path, if the user belongs to a group which
        # has write access to this element then allow the request
        for parent in self.get_path_parents(path):
            try:
                allowed_groups = self.permissions[parent]
            except KeyError:
                continue
            if not groups.isdisjoint(allowed_groups):
                return True
        return False

    @staticmethod
    def get_path_parents(path):
        parts = path.strip('/').split('/')
        initial = [] if parts[0] == '' else ['']
        return initial + ['/'.join(parts[:n+1]) for n in range(len(parts))]


class User(object):

    def __init__(self, manager, groups, user_id):
        self.manager = manager
        self.groups = groups
        self.user_id = user_id

    def has_read_access(self, path):
        return self.manager.has_read_access(self.groups, path)

    def has_write_access(self, path):
        return self.manager.has_write_access(self.groups, path)

    def __str__(self):
        return '<%s>' % self.user_id
