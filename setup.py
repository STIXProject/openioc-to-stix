#!/usr/bin/env python
# Copyright (c) 2015 - The MITRE Corporation
# For license information, see the LICENSE.txt file

from os.path import abspath, dirname, join
import sys

from setuptools import setup, find_packages

BASE_DIR = dirname(abspath(__file__))
VERSION_FILE = join(BASE_DIR, 'openioc2stix', 'version.py')

def get_version():
    with open(VERSION_FILE) as f:
        for line in f.readlines():
            if line.startswith("__version__"):
                version = line.split()[-1].strip('"')
                return version
        raise AttributeError("Package does not have a __version__")


py_maj, py_minor = sys.version_info[:2]

if py_maj != 2:
    raise Exception('openioc-to-stix required Python 2.6/2.7')

if (py_maj, py_minor) < (2, 6):
    raise Exception('openioc-to-stix requires Python 2.6/2.7')

fn_readme = join(BASE_DIR, "README.rst")
with open(fn_readme) as f:
    readme = f.read()

install_requires = [
    'cybox>=2.1.0.13',
    'lxml>=3.3.5',
    'mixbox>=1.0.1',
    'stix>=1.2.0.2',
]

# Python 2.6 does not come with argparse
try:
    import argparse
except ImportError:
    install_requires.append('argparse')


setup(
    name='openioc-to-stix',
    description='Converts OpenIOC documents into STIX/CybOX documents.',
    author='The MITRE Corporation',
    author_email='stix@mitre.org',
    url='http://stix.mitre.org/',
    version=get_version(),
    packages=find_packages(),
    scripts=['openioc-to-stix.py', 'openioc-to-cybox.py'],
    include_package_data=True,
    install_requires=install_requires,
    long_description=readme,
    keywords="stix cybox openioc xml openioc-to-stix openioc-to-cybox"
)
