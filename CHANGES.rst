Changelog for Jupyter-O2
------------------------

1.0.5 - 2021-06-06
~~~~~~~~~~~~~~~~~~~~~~~~

**Removed:**

* This version removes compatibility with Python 2.7,
  which has not been supported since version 1.0.2.

**Improvements:**

- Added warning for common error if two-factor authentication is not used

**Fixes:**

- Fixed moving to a new jupyter port if the original port was occupied

**Updates:**

- Updated packaging system for PEP 517
- Raised minimum dnspython version to 2.0

1.0.4 - 2021-02-02
~~~~~~~~~~~~~~~~~~~~~~~~

**New:**

- Added option to change SLURM partition

**Fixes:**

- #3 Improved handling of hostname decode error

1.0.2 - 2020-08-24
~~~~~~~~~~~~~~~~~~~~~~~~

**New:**

- #6 Jupyter-O2 now requires only a single ssh session.
  The second ssh session is now disabled by default and can be
  re-enabled in the config file.

1.0.1 - 2020-07-14
~~~~~~~~~~~~~~~~~~~~~~~~

**Enhancements:**

- #4 Improved README

**Fixes:**

- #3 Made hostname decode error more readable
- #5 Disabled timeout when starting interactive session


1.0.0 - 2019-05-30
~~~~~~~~~~~~~~~~~~~~~~~~

**Fixes:**

- #3 Improve exception handling
- Fix handling of alternate ports

0.2.9 - 2018-12-04
~~~~~~~~~~~~~~~~~~~~~~~~

**New:**

- #1 Initial implementation of Duo 2FA handler to address new O2 login procedures

For information about older versions, see their `release notes`__.

__ https://github.com/aaronkollasch/jupyter-o2/releases
