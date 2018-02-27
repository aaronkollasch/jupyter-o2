===============
Jupyter-O2 tips
===============

--------------------------------------------------------------------------------------------------
Useful jupyter addons
--------------------------------------------------------------------------------------------------

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Kernels
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are `many kernels <https://github.com/jupyter/jupyter/wiki/Jupyter-kernels>`__
available for Jupyter, allowing the user to write notebooks in their
desired language.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
`bash_kernel <https://pypi.python.org/pypi/bash_kernel>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Since Jupyter-O2 runs Jupyter on an interactive node, bash notebooks
can be used to document your session on O2, including commands and
outputs, without using SLURM to submit additional jobs.

``%%bash`` can be used to run a ``bash`` command in kernels that support
it, but it does not remember your working directory or other variables
from previous cells.

Just be sure that your node has sufficient memory for the desired tasks,
or you could find your notebook server shutting down unexpectedly. SLURM
jobs can also be submitted and monitored from within a notebook to avoid
this issue.

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
`jupyter contrib nbextensions <https://github.com/ipython-contrib/jupyter_contrib_nbextensions>`__
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

jupyter contrib nbextensions adds a useful nbextensions configuration
tab to the main jupyter site. It also includes many useful extensions.

~~~~~~~~~~~~~~~~~~~~~~~~~~~
AutoSaveTime (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set the auto-save time to 2 minutes to reduce the risk of losing changes
due to a lost connection or closure of the interactive node.
For example, the connection could time out or the node could exceed its time limit.

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
`JupyterLab <https://github.com/jupyterlab/jupyterlab>`__
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

While JupyterLab is currently in beta, it offers a more complete
environment than Jupyter Notebook, and it is now
`ready for users <https://blog.jupyter.org/jupyterlab-is-ready-for-users-5a6f039b8906>`__.
With tabs for notebooks, terminals, consoles, and text editors, and an integrated file browser,
you could run almost anything you need on O2 from a single browser window.

--------------------------------------------------------------------------------------------------
Troubleshooting
--------------------------------------------------------------------------------------------------

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
nbsignatures.db
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If jupyter hangs when opening notebooks for the first time in any
session, and the console shows error messages such as:

.. code-block::

    > The signatures database cannot be opened; maybe it is corrupted or encrypted.
    > Failed commiting signatures database to disk.

Disabling the signatures database may be the best option, since there is
no non-networked file system shared between all the interactive compute
nodes.

1. Enter an interactive session and generate a notebook config using
   ``jupyter notebook --generate-config``
2. In ``~/.jupyter/jupyter_notebook_config.py`` set
   ``c.NotebookNotary.db_file = ':memory:'``

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
X11 error
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you see ``srun: error: x11: no local DISPLAY defined``, try logging
in to the server with ``ssh -X`` and check your DISPLAY using
``echo $DISPLAY``. There should be a string printed in response.

If ``$DISPLAY`` is empty, try reinstalling
`XQuartz <https://www.xquartz.org/>`__, or run Jupyter-O2 with the
``-Y`` argument to enable trusted X11 forwarding (less secure).
