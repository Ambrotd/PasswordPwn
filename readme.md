## PasswdPWN

### Description

The program checks against the haveIbeenPwn API if your password has been leaked.
It is secure because the password is hashed locally and only the first 5 hex characters of the hash are sent to the API.
The results are compared locally with the full hash.

In summary your password never leave your computer so it is safe to use, just remember to clean your cli history.

### Installation

1. Clone the repo with ``git clone https://github.com/Ambrotd/PasswordPwn.git``
2. Get in the PasswordPwn directory ``cd PasswordPwn``
3. Install the requirements ``pip3 install -r requirements.txt``

And it should be ready to use.

### Usage
#### Password checking
It accepts one or more passwords using the parameter -p or --passwords

Example: ``python3 PasswdPwn.py -p mypass1 mypass2``

#### Email checking
It accepts one or more emails using the parameter -e or --email. 
- Check your username against all the domains:
``python3 PasswdPwn.py -e username``

- Check your domain for leaks:
``python3 PasswdPwn.py -e @domain.xyz``

- Check the complete email:
``python3 PasswdPwn.py -e username@domain.xyz``

