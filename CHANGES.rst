Changelog for Jupyter-O2
========================

Unreleased
----------

Added
^^^^^

- Better error message if two-factor authentication fails
- Warning if two-factor authentication is set incorrectly
  for the computer's network location

1.0.5 - 2021-06-06
------------------

Removed
^^^^^^^

- This version removes compatibility with Python 2.7,
  which has not been supported since version 1.0.2.

Added
^^^^^

- Warning message for a common error if two-factor
  authentication is not used

Fixed
^^^^^

- Fixed moving to a new jupyter port if the original port was occupied

Updated
^^^^^^^

- Packaging system now supports PEP 517
- Raised minimum dnspython version to 2.0

1.0.4 - 2021-02-02
------------------

Added
^^^^^

- Option to change SLURM partition

Fixed
^^^^^

- #3 Improved handling of hostname decode error

1.0.2 - 2020-08-24
------------------

Added
^^^^^

- #6 Jupyter-O2 now requires only a single ssh session.
  The second ssh session is now disabled by default and can be
  re-enabled in the config file.

1.0.1 - 2020-07-14
------------------

Added
^^^^^

- #4 Improved README

Fixed
^^^^^

- #3 Made hostname decode error more readable
- #5 Disabled timeout when starting interactive session


1.0.0 - 2019-05-30
------------------

Fixed
^^^^^

- #3 Improve exception handling
- Fix handling of alternate ports

0.2.9 - 2018-12-04
------------------

Added
^^^^^

- #1 Initial implementation of Duo 2FA handler to address new O2 login procedures

For information about older versions, see their `release notes`__.

__ https://github.com/aaronkollasch/jupyter-o2/releases
