import errno
import functools
import logging
import os
import socket
import threading

import paramiko


class SFTPServer(object):
    """
    Create an SFTP server which serves the files in `root` and authenticates
    itself with the supplied `host key` file.

    `serve_forver` starts the server listening on the supplied host and port
    and handles each connection in a new thread.

    A `get_user` method must be supplied. This should accept a username and
    password and return either a User object or None if the credentials are
    invalid.

    A User object should implement two methods: `has_read_access` and
    `has_write_access`.  Each method should accept a path (relative to `root`)
    and return True or False appropriately. Users should also have a sensible
    `__str__` representation for use in logging.
    """

    SOCKET_BACKLOG = 10

    def __init__(self, root, host_key_path, get_user=None):
        self.root = root
        self.host_key = paramiko.RSAKey.from_private_key_file(host_key_path)
        if get_user is not None:
            self.get_user = get_user

    def serve_forever(self, host, port):
        server_socket = socket.socket()
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        server_socket.bind((host, port))
        server_socket.listen(self.SOCKET_BACKLOG)
        while True:
            conn = server_socket.accept()[0]
            self.start_sftp_session(conn)

    def start_sftp_session(self, conn):
        transport = paramiko.Transport(conn)
        transport.add_server_key(self.host_key)
        transport.set_subsystem_handler(
            'sftp', paramiko.SFTPServer, SFTPInterface, self.root)
        # The SFTP session runs in a separate thread. We pass in `event`
        # so `start_server` doesn't block; we're not actually interested
        # in waiting for the event though.
        transport.start_server(
                server=SSHInterface(self.get_user),
                event=threading.Event())

    def get_user(self, username, password):
        raise NotImplementedError()


class SSHInterface(paramiko.ServerInterface):

    def __init__(self, get_user):
        self.get_user = get_user

    def check_auth_password(self, username, password):
        user = self.get_user(username, password)
        if user:
            logging.info((u'Auth successful for %s' % username).encode('utf-8'))
            self.user = user
            return paramiko.AUTH_SUCCESSFUL
        else:
            logging.info((u'Auth failed for %s' % username).encode('utf-8'))
            return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        else:
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class PermissionDenied(Exception):
    pass


def sftp_response(fn):
    """
    Dectorator which converts exceptions into appropriate SFTP error codes,
    returns OK for functions which don't have a return value
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            value = fn(*args, **kwargs)
        except (OSError, IOError) as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        except PermissionDenied:
            return paramiko.SFTP_PERMISSION_DENIED
        if value is None:
            return paramiko.SFTP_OK
        else:
            return value
    return wrapper


def log_event(method):
    """
    Decorator which logs SFTP events along with the current user
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        string_args = u':'.join([arg for arg in args if isinstance(arg, basestring)])
        msg = u'%s:%%s:%s:%s' % (method.__name__, self.user, string_args)
        try:
            response = method(self, *args, **kwargs)
        except Exception:
            logging.info((msg % 'error').encode('utf-8'))
            raise
        else:
            logging.info((msg % 'ok').encode('utf-8'))
        return response
    return wrapper


class SFTPInterface(paramiko.SFTPServerInterface):

    FILE_MODE = 0664
    DIRECTORY_MODE = 0775

    def __init__(self, server, root):
        self.user = server.user
        self.root = root

    def realpath_for_read(self, path):
        return self._realpath(path, self.user.has_read_access)

    def realpath_for_write(self, path):
        return self._realpath(path, self.user.has_write_access)

    def _realpath(self, path, permission_check):
        path = self.canonicalize(path).lstrip('/')
        if not permission_check(path):
            raise PermissionDenied()
        return os.path.join(self.root, path)

    @sftp_response
    @log_event
    def open(self, path, flags, attr):
        # We ignore `attr` -- we choose the permissions around here,
        # not the client
        read_only = (flags == os.O_RDONLY)
        if read_only:
            realpath = self.realpath_for_read(path)
        else:
            realpath = self.realpath_for_write(path)
        fd = os.open(realpath, flags, self.FILE_MODE)
        fileobj = os.fdopen(fd, flags_to_string(flags), self.FILE_MODE)
        handle = SFTPFileHandle(flags)
        handle.readfile = fileobj
        if not read_only:
            handle.writefile = fileobj
        return handle

    @sftp_response
    @log_event
    def list_folder(self, path):
        realpath = self.realpath_for_read(path)
        return [sftp_attributes(os.path.join(realpath, filename))
                    for filename in os.listdir(realpath)]

    @sftp_response
    @log_event
    def stat(self, path):
        return sftp_attributes(self.realpath_for_read(path), follow_links=True)

    @sftp_response
    def lstat(self, path):
        return sftp_attributes(self.realpath_for_read(path))

    @sftp_response
    @log_event
    def remove(self, path):
        os.unlink(self.realpath_for_write(path))

    @sftp_response
    @log_event
    def rename(self, oldpath, newpath):
        realpath_old = self.realpath_for_write(oldpath)
        realpath_new = self.realpath_for_write(newpath)
        # SFTP dictates that renames should be non-destructive
        # (Yes, there's a race-condition here, but we can live
        # with it)
        if os.path.exists(realpath_new):
            raise OSError(errno.EEXIST)
        os.rename(realpath_old, realpath_new)

    @sftp_response
    @log_event
    def mkdir(self, path, attr):
        # We ignore `attr` -- we choose the permissions around here,
        # not the client
        os.mkdir(self.realpath_for_write(path), self.DIRECTORY_MODE)

    @sftp_response
    @log_event
    def rmdir(self, path):
        os.rmdir(self.realpath_for_write(path))

    @sftp_response
    @log_event
    def chattr(self, path, attr):
        # We flat-out lie and pretend that we've executed this
        # but don't actually do anything
        pass

    @sftp_response
    @log_event
    def readlink(self, path):
        # We only allow `readlink` on relative links that stay within the
        # shared root directory
        realpath = self.realpath_for_read(path)
        target = os.readlink(realpath)
        if os.path.isabs(target):
            return paramiko.SFTP_OP_UNSUPPORTED
        target_abs = os.path.normpath(os.path.join(
            os.path.dirname(realpath), target))
        if not target_abs.startswith(self.root + '/'):
            return paramiko.SFTP_OP_UNSUPPORTED
        return target


class SFTPFileHandle(paramiko.SFTPHandle):

    @sftp_response
    def chattr(self, path, attr):
        # We flat-out lie and pretend that we've executed this
        # but don't actually do anything
        pass

    @sftp_response
    def stat(self):
        return paramiko.SFTPAttributes.from_stat(
                os.fstat(self.readfile.fileno()))


def sftp_attributes(filepath, follow_links=False):
    """
    Return an SFTPAttributes object for the given path
    """
    filename = os.path.basename(filepath)
    stat = os.stat if follow_links else os.lstat
    return paramiko.SFTPAttributes.from_stat(
        stat(filepath), filename=filename)


def flags_to_string(flags):
    """
    Convert bitmask of flags as taken by `os.open` into a mode string
    as taken by `open`
    """
    if flags & os.O_WRONLY:
        if flags & os.O_APPEND:
            mode = 'a'
        else:
            mode = 'w'
    elif flags & os.O_RDWR:
        if flags & os.O_APPEND:
            mode = 'a+'
        else:
            mode = 'r+'
    else:
        mode = 'r'
    # Force binary mode
    mode += 'b'
    return mode
