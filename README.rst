===========
Jupyter-O2
===========

Jupyter-O2 is a command-line tool that automatically runs Jupyter on
Orchestra 2, an HPC cluster managed by the HMS Resesarch Computing group.

Installation
------------------------------
First, follow the `O2 wiki's procedure <https://wiki.rc.hms.harvard.edu/display/O2/Jupyter+on+O2>`_
to set up Jupyter for your account on O2.

Next, install Jupyter-O2.

.. code-block:: console

    $ pip install jupyter-o2

Then, run ``jupyter-o2 --generate-config`` and open the generated file,  ``jupyter-o2.cfg``.

.. warning::

    If updating from 0.2.3 or earlier, copy ``jupyter-o2.cfg`` to a temporary location,
    or it will be deleted automatically.
    You may also copy ``jupyter-o2.cfg`` to a location listed by ``jupyter-o2 --paths``.
    This will no longer be an issue from 0.2.4 onwards, as the file is not added during installation.

Edit ``jupyter-o2.cfg`` according to its instructions, particularly the
``DEFAULT_USER``, ``MODULE_LOAD_CALL``, and ``SOURCE_JUPYTER_CALL`` fields.

For more info on setting up Jupyter and troubleshooting Jupyter-O2, see the `jupyter-o2 tips`_.

.. _jupyter-o2 tips: https://github.com/AaronKollasch/jupyter-o2/blob/master/jupyter_o2_tips.rst

Usage
------------------------------
.. code-block:: console

    $ jupyter-o2 [subcommand]

Examples: ``jupyter-o2 notebook`` or ``jupyter-o2 lab``
(try it with `JupyterLab <https://github.com/jupyterlab/jupyterlab>`__!)

If Jupyter is installed on your machine,
Jupyter-O2 can also be run as a Jupyter subcommand, e.g. ``jupyter o2 notebook``.

For info on the Jupyter-O2 command-line options, use ``jupyter-o2 --help``.

Requirements and compatibility
------------------------------
* python 2.7 and 3.6 have been tested.
* pexpect.pxssh
* POSIX: Jupyter-O2 has been tested on MacOS. It may work on Linux, and on Windows it should
  require Cygwin and Cygwin's version of Python.

Optional installs
------------------------------
* pinentry (a command line tool used instead of getpass)
