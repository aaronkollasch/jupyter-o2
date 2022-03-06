===========
Jupyter-O2
===========

|PyPI version| |PyPI pyversions| |PyPI license|

.. |PyPI version| image:: https://img.shields.io/pypi/v/jupyter-o2.svg
   :target: https://pypi.python.org/pypi/jupyter-o2/

.. |PyPI pyversions| image:: https://img.shields.io/pypi/pyversions/jupyter-o2.svg
   :target: https://pypi.python.org/pypi/jupyter-o2/

.. |PyPI license| image:: https://img.shields.io/pypi/l/jupyter-o2.svg
   :target: https://pypi.python.org/pypi/jupyter-o2/

Jupyter-O2 is a command-line tool that remotely runs Jupyter on
Orchestra 2 (O2), an HPC cluster managed by the HMS Research Computing group.

Installation
============
First, follow the `O2 wiki's procedure <https://wiki.rc.hms.harvard.edu/display/O2/Jupyter+on+O2>`_
to set up Jupyter for your account on O2.
(If you have already installed Jupyter on O2, you can skip this step.)

Next, on your local machine:

Install Jupyter-O2.

.. code-block:: bash

    pip install jupyter-o2

Then, generate the config file.

.. code-block:: bash

    jupyter-o2 --generate-config

Follow the printed path to ``jupyter-o2.cfg`` and edit according to its instructions, particularly the
``DEFAULT_USER`` and ``INIT_JUPYTER_COMMANDS`` fields.
You may copy this file to any of the locations listed by ``jupyter-o2 --paths`` for easier access.

Make sure you have X11 forwarding active (install `XQuartz <https://www.xquartz.org/>`_ if on a Mac).

For more info on setting up Jupyter and troubleshooting Jupyter-O2, see the `jupyter-o2 tips`_.

.. _jupyter-o2 tips: https://github.com/aaronkollasch/jupyter-o2/blob/master/jupyter_o2_tips.rst

Requirements and compatibility
------------------------------
* python 3.6+
* pexpect 4.5+
* POSIX: Jupyter-O2 requires a POSIX environment such as macOS or Linux.
  If you have a Windows machine, you can try using `WSL2`_

.. _WSL2: https://github.com/aaronkollasch/jupyter-o2/blob/master/jupyter_o2_tips.rst#run-on-windows-using-wsl2

Usage
=====
Jupyter-O2 should be run locally using the following command format:

.. code-block:: bash

    jupyter-o2 [subcommand]

Examples: ``jupyter-o2 notebook`` or ``jupyter-o2 lab``
(try `JupyterLab <https://github.com/jupyterlab/jupyterlab>`__!)

This will automate the "Opening a Notebook" procedure
on the `O2 wiki <https://wiki.rc.hms.harvard.edu/display/O2/Jupyter+on+O2>`_.

Note that if Jupyter is installed on your machine, Jupyter-O2 can also be run as a Jupyter subcommand:

.. code-block:: bash

    jupyter o2 lab

For info on the Jupyter-O2 command-line options, use ``jupyter-o2 --help``.

Two-factor authentication
-------------------------
Jupyter-O2 detects the Duo two-factor authentication prompt and
requests a Duo push by default (code 1).
To send a pre-generated code, use the argument ``--2fa-code <code>``,
replacing ``<code>`` with your code.

*Experimental: use* ``--2fa-code interact`` *to interactively respond to the Duo prompt.
This allows you to request a phone or text push and enter the code you receive.*
