#!/usr/bin/env python
# # Copyright (c) 2017 - The MITRE Corporation
# For license information, see the LICENSE.txt file

from os.path import abspath, dirname, join
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


def get_long_description():
    with open("README.rst") as f:
        return f.read()


setup(
    name='openioc-to-stix',
    description='Converts OpenIOC documents into STIX/CybOX documents.',
    long_description=get_long_description(),
    author='The MITRE Corporation',
    author_email='stix@mitre.org',
    url='http://stix.mitre.org/',
    version=get_version(),
    packages=find_packages(),
    scripts=['openioc-to-stix.py', 'openioc-to-cybox.py'],
    install_requires=[
        'argparse;python_version == "2.6"',
        'cybox>=2.1.0.13',
        'lxml>=3.3.5',
        'mixbox>=1.0.1',
        'stix>=1.2.0.2',
    ],
    keywords="stix cybox openioc xml openioc-to-stix openioc-to-cybox",
    license="BSD",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
    ],
)
