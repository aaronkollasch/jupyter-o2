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

Then, find the ``jupyter-o2.cfg`` file in ``etc/jupyter-o2``.
Run ``jupyter-o2 --paths`` to see possible and current locations.

    ``jupyter-o2.cfg`` should be installed upon setup.
    If not, you may also copy ``jupyter_o2/jupyter-o2.cfg`` into any location in ``jupyter-o2 --paths``.

Edit ``jupyter-o2.cfg`` according to its instructions, particularly the ``DEFAULT_USER``, ``MODULE_LOAD_CALL``,
and ``SOURCE_JUPYTER_CALL`` fields.

    Update: If upgrading from version 0.1 to 0.2, add ``DEFAULT_USER = <user>`` to ``jupyter-o2.cfg``
    under ``[Defaults]``, substituting your O2 username for ``<user>``.

For more info on setting up Jupyter and troubleshooting Jupyter-O2, see `jupyter_o2_tips.rst`_.

.. _jupyter_o2_tips.rst: https://github.com/AaronKollasch/jupyter-o2/blob/master/jupyter_o2_tips.rst

Usage
------------------------------
.. code-block:: console

    $ jupyter-o2 [subcommand]

Example: ``jupyter-o2 notebook``

If Jupyter is installed on your machine,
Jupyter-O2 can also be run as a Jupyter subcommand, e.g. ``jupyter o2 notebook``.

    This will launch an X11-enabled ssh, start an interactive node running jupyter notebook,
    ssh into that interactive node to allow requests to be forwarded,
    and finally open the notebook in your browser.

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
