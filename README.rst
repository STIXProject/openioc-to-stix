openioc-to-stix
===============

Generates STIX Indicator Output from an OpenIOC v1.0 XML File.


Overview
--------

The OpenIOC to STIX script generates STIX Indicators from an OpenIOC v1.0
XML file.

* Compatible with OpenIOC v1.0
* Generates STIX v1.2 and CybOX v2.1.1 content.

Please refer to the following websites for more information about the STIX,
CybOX, and OpenIOC efforts.

* STIX - http://stix.mitre.org
* CybOX - http://cybox.mitre.org
* OpenIOC - http://www.openioc.org

Requirements
------------

* Python 2.7
* python-stix >= v1.2.0.0 (stable)
* python-cybox >= 2.1.0.12 (stable)

**Note:** This script was written and tested with Python 2.7 and may not be
compatible with other Python versions.

Installation
------------

Extract included files into your directory of choice. Please refer to the
``requirements.txt`` file for dependencies.

Install dependencies with pip:

::

    $ pip install -r requirements.txt

You can also install **openioc-to-stix** into your ``site-packages`` and ``PATH``
by using `pip`.

::

    $ cd /path/to/cloned/openioc-to-stix/repo/
    $ pip install .

**Note:** Running ``python setup.py install`` directly may install unstable, pre-release versions of python-stix and python-cybox. THESE WILL NOT WORK WITH OPENIOC-TO-STIX.

Usage
-----

There are two main command line parameters for this script:

::

    -i: the path to the input OpenIOC XML file
    -o: the path to the output STIX XML file

To use the script, run the following command:

::

    $ python openioc_to_stix.py -i <OpenIOC XML file> -o <STIX XML file>

Unsupported indicator items or those that error out during translation will be
translated into an empty Observable with a description of the error in order
to retain structural consistency between the input OpenIOC document and
output STIX document.


Package Contents
----------------

* ``README``: This file.
* ``openioc-to-stix.py``: OpenIOC XML to STIX XML Python script.
* ``openioc-to-cybox.py``: OpenIOC XML to CybOX XML Python converter script
  which this script wraps.
* ``openioc2stix/``: Top-level API package.
* ``LICENSE.txt``: Terms of use for this script.
* ``examples/*.xml``: Sample input and output XML files.


TERMS
-----
BY USING OPENIOC-TO-STIX YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND CONDITIONS
OF USE. IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE OPENIOC-TO-STIX.

For more information, please refer to the LICENSE.txt file
