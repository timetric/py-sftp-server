Py SFTP Server
==============

A simple SFTP server with pluggable authentication and permissions backends.

Uses `paramiko`_ to handle the actual SFTP & SSH protocol implementation.

Written at Timetric to provide a simple shared file server which integrated with
our existing LDAP infrastructure and permissions model.

See ``example_server.py`` for an example of how the authentication and authorisation backends
can be plugged together.

See the module docstrings for details of the APIs.

.. _paramiko: http://www.paramiko.org/
