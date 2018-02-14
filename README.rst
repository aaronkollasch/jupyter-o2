===========
jupyter-o2
===========

Jupyter-O2 is a command-line tool that automatically connects to
and runs Jupyter on Orchestra 2, an HPC cluster managed by the HMS Resesarch Computing group.

Installation
------------------------------
First, follow the `O2 wiki's procedure <https://wiki.rc.hms.harvard.edu/display/O2/Jupyter+on+O2>`_
to set up Jupyter for your account on O2.

Next, install Jupyter-O2.::

    $ pip install jupyter-o2

Then, find the ``jupyter-o2.cfg`` file in ``etc/jupyter-o2``, where ``etc`` is located either in the
environment root or the system-wide ``/etc`` directory.
Edit this file according to its instructions, particularly ``MODULE_LOAD_CALL`` and ``SOURCE_JUPYTER_CALL``.

Note: `jupyter-o2.cfg`` should be installed upon setup.
If not, you may also copy ``jupyter_o2/jupyter-o2.cfg`` into your home folder as ``.jupyter-o2.cfg``.

Usage
------------------------------
::

    $ jupyter_o2 <USER> <subcommand>

Example: ``jupyter_o2 js123 notebook``
    This will launch an X11-enabled ssh, start an interactive node running jupyter notebook,
    ssh into that interactive node to allow requests to be forwarded,
    and finally open the notebook in your browser.

Requirements and compatibility
------------------------------
* python 2.7 or 3.6 (tested)
* Pexpect
* POSIX: Jupyter-O2 has been tested on MacOS. It may work on Linux and it would likely require
  both Cygwin and a Cygwin version of Python to work on Windows (for Pexpect and SSH).

Optional installs
------------------------------
* pinentry (a command line tool)


