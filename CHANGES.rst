Changelog for Jupyter-O2
========================

1.0.4
-----

* Update version
* Update date
* Update README
* Add Python 3.9 and remove 2.7 from classifiers
* Improve stability of get\_hostname()
* Fix incorrect config partition identifier
* Improve syntax and match current pxssh login header
* Add option to use a different SLURM partition

1.0.2
-----

* Make second ssh session optional
* Add port number to interactive call template

1.0.1
-----

* Add instructions to hostname decode error
* Update date
* Increment version
* Make hostname decode error more readable
* Update copyright year
* Update README
* Disable interactive session timeout by default
* Clarify README
* Update README

1.0.0
-----

* Update README
* Update version.py
* Update information and version
* Fix incorrect jp\_port variable in SSH options
* Improve exception handling

0.2.9
-----

* Implement Duo two-factor authentication handler
* Add timeout for starting internal interactive session
* Deprecate MODULE\_LOAD\_CALL and SOURCE\_JUPYTER\_CALL in jupyter-o2.cfg
* Update jupyter\_o2\_tips.rst

0.2.8
-----

* Add config settings to address changes to O2 configuration

0.2.7
-----

* Fix cmd\_exists() for both positive and negative cases

0.2.6
-----

* Make SOURCE\_JUPYTER and MODULE\_LOAD calls accept full commands
* Fix error in pysectools.cmd\_exists() for Linux
* Update README.rst
* Update README.rst
* Remove [DIR] option from --generate-config and improve README.rst
* Add more configuration options for different environments
* Added recognition of SSH authentication errors for interactive nodes
* Add --no-browser argument
* Split up JupyterO2.connect() and add CustomSSH helper methods
* Fix test\_jupyter\_o2\_config\_manager.py
* Update miscellany; Use python types in JO2\_DEFAULTS rather than strings

0.2.5
-----

* Make config optional in JupyterO2.\_\_init\_\_() and fix test issues
* Make config optional in JupyterO2.\_\_init\_\_()
* Improve launch time by postponing or removing slow imports
* Compartmentalize config management
* Update README.rst

0.2.4
-----

* Fix tests in Python 2
* Add option to force getpass instead of pinentry
* Improve command line output in verbose mode and fix test errors
* Replace print statements with a log entry
* Add more flexibility in providing Jupyter initialization commands
* Add --version argument and check for sendlineprompt exit status
* Switch to generating jupyter-o2.cfg from a command and not on install
* Add and use CustomSSH.sendpass()

0.2.3
-----

* Recommend JupyterLab in the README
* Add JupyterO2 Exceptions and run function
* test JupyterO2 init
* Move sendline debug log to CustomSSH
* Improve connect() flow and readability
* Fix port\_retries load from config as int
* Streamline JupyterO2.connect()
* Add tests, open port search, and run\_jupyter\_call\_format config item
* Enhance messages in verbose mode
* jupyter\_o2\_tips.rst updates
* now uses DEFAULT\_JP\_SUBCOMMAND (will be optional as a command line input on next release)

0.2.2
-----

* updated logging in jupyter\_o2.py and use of print() in pysectools.py
* fixed a compatibility issue with python 2.7
* fixed a compatibility issue with python 2.7

0.2.1
-----

* README.rst edits
* README.rst edits
* Reduced privacy of some JupyterO2 class variables to protected
* jupyter\_o2\_tips.rst update
* Added jupyter-o2 --paths argument Edited README.rst
* Added logging and a verbose flag. Added instructions for accessing jupyter-o2.cfg or finding its location
* More info on finding the etc/jupyter-o2 directory

0.2.0
-----

* Made USER an optional argument specified in jupyter-o2.cfg

0.1.4
-----

* Update README.rst
* README.rst, requirements.txt updates
* moved cmd\_exists to pysectools updated jupyter-o2 bin file
* update jupyter\_o2\_tips

0.1.3
-----

* readme update
* readme update
* add jupyter\_o2\_tips update setup

0.1.2
-----

* include bin file

0.1.1
-----

* reordered config hierarchy
* readme update

0.1.0
-----

* readme update
* setup update
* readme update
* readme update
* pbr troubleshooting
* Update README.rst
* setup and readme updates
* init info
* Initial commit
