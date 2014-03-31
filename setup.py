import os
import io
from setuptools import setup


PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))

def read(*path):
    full_path = os.path.join(PROJECT_ROOT, *path)
    with io.open(full_path, 'r', encoding='utf-8') as f:
        return f.read()

setup(
    name='sftp_server',
    version='0.1',
    author='David Evans',
    author_email='devans@timetric.com',
    url='https://github.com/timetric/py-sftp-server',
    packages=['sftp_server'],
    requires=['paramiko'],
    license='MIT',
    description="SFTP server with pluggable permissions and authentication backends",
    long_description=read('README.rst'),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
    ],
)
