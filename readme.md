## PasswdPWN

### Description

The program check against the haveIbeenPwn API is your password have been leaked.
It is secure because the password is hashed locally and only the first 5 hex characters of the hash are sent to the API.
The results are compared locally with the full hash.

In summary your password never leave your computer so it is safe to use, just remember to clean your cli history.

### Installation

1.Clone the repo with ``git clone https://github.com/Ambrotd/PasswordPwn.git``
2.Get in the PasswordPwn directory ``cd PasswdPwn``
3.Install the requirements ``pip3 install -r requirements.txt``

And it should be ready to use.

### Usage

It accepts one or more passwords using the parameter -p or --passwords

Example: ``python3 PasswdPwn.py -p mypass1 mypass2``
