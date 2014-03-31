import unittest

from sftp_server.permissions_manager import PermissionsManager


class TestDirectoryPermissions(unittest.TestCase):

    permissions = {
        'dir_1': set(['group_1']),
        'dir_1/subdir_2': set(['group_2']),
        'dir_2': set(['group_2']),
        'shared': set(['group_1', 'group_2']),
    }

    users = {
        'no_privs': ['no_priv_group'],
        'min_privs': ['staff'],
        'user_1': ['staff', 'group_1'],
        'user_2': ['staff', 'group_2'],
        'admin': ['staff', 'group_1', 'group_2']
    }

    def authenticate(self, username, password):
        try:
            return self.users[username]
        except KeyError:
            return None

    def setUp(self):
        self.manager = PermissionsManager(self.permissions,
                required_group='staff',
                authenticate=self.authenticate)

    def test_get_path_parents(self):
        for path, parents in [
                ('', ['']),
                ('one', ['', 'one']),
                ('one/two', ['', 'one', 'one/two']),
                ('one/two/', ['', 'one', 'one/two']),
                ('one/two/three', ['', 'one', 'one/two', 'one/two/three']),
            ]:
            self.assertEqual(parents,
                    PermissionsManager.get_path_parents(path))

    def test_unknown_user_returns_falsey(self):
        self.assertFalse(self.manager.get_user('unknown', 'nopass'))

    def test_user_to_string_contains_id(self):
        user = self.manager.get_user('min_privs', 'password')
        self.assertIn('min_privs', '%s' % user)

    def test_non_staff_user_rejected(self):
        self.assertFalse(self.manager.get_user('no_privs', 'password'))

    def test_staff_users_have_read_access_to_all(self):
        for username in self.users.keys():
            if username == 'no_privs':
                continue
            user = self.manager.get_user(username, 'password')
            for path in self.permissions.keys():
                self.assertTrue(user.has_read_access(path))

    def test_correct_users_have_write_access(self):
        write_access = {
            'dir_1': set(['user_1', 'admin']),
            'dir_1/subdir_2': set(['user_1', 'user_2', 'admin']),
            'dir_2': set(['user_2', 'admin']),
            'shared': set(['user_1', 'user_2', 'admin']),
        }
        for path, users_with_write_access in write_access.items():
            for username in self.users.keys():
                user = self.manager.get_user(username, 'password')
                has_write = (user and user.has_write_access(path))
                if username in users_with_write_access:
                    self.assertTrue(has_write,
                            msg='%s should have write access to %s' % (username, path))
                else:
                    self.assertFalse(has_write,
                            msg='%s should not have write access to %s' % (username, path))
