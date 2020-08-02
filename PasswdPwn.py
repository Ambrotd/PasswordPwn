import requests
import hashlib
import sys
import argparse

'''
Using GET https://api.pwnedpasswords.com/range/{first 5 hash chars} the k-model allows anonymity as the full hash is not getting
out of your computer
'''
class bColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLACK = '\u001b[30m'
    RED = '\u001b[31m'
    GREEN = '\u001b[32m'
    YELLOW = '\u001b[33m'
    BLUE = '\u001b[34m'
    MAGENTA = '\u001b[35m'
    CYAN = '\u001b[36m'
    WHITE = '\u001b[37m'
    RESET = '\u001b[0m'

API_URL = 'https://api.pwnedpasswords.com/range/'

def passwd_api_check(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    hash_to_api, hash_to_check = sha1[0:5], sha1[5:]
    check_url = API_URL + hash_to_api
    r = requests.get(check_url)
    if r.status_code != 200:
        raise RuntimeError(f'Api is down, error {r.status_code}; Check the api')
    hash_generator = (i.split(':') for i in r.text.splitlines())
    for h, count in hash_generator:
        if h == hash_to_check:
            return count
    return 0

def main():

    parser = argparse.ArgumentParser()
    banner = ''' 

8888888b.                                                888 8888888b.  888       888 888b    888 
888   Y88b                                               888 888   Y88b 888   o   888 8888b   888 
888    888                                               888 888    888 888  d8b  888 88888b  888 
888   d88P  8888b.  .d8888b  .d8888b  888  888  888  .d88888 888   d88P 888 d888b 888 888Y88b 888 
8888888P"      "88b 88K      88K      888  888  888 d88" 888 8888888P"  888d88888b888 888 Y88b888 
888        .d888888 "Y8888b. "Y8888b. 888  888  888 888  888 888        88888P Y88888 888  Y88888 
888        888  888      X88      X88 Y88b 888 d88P Y88b 888 888        8888P   Y8888 888   Y8888 
888        "Y888888  88888P'  88888P'  "Y8888888P"   "Y88888 888        888P     Y888 888    Y888 
                                                                                                  
            {}Check if your passwd has been leaked without compromising it{}
                                By {}Ambrotd{}
    
    '''.format(bColors.WARNING, bColors.ENDC, bColors.RED, bColors.ENDC)
    print(f'{bColors.OKBLUE}{banner}{bColors.ENDC}')
    parser.add_argument("-p", "--passwords", nargs='+', type=str, dest='passwords',
                        help="Insert the passwords to check separated by space")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if type(args.passwords) == list:
        for password in args.passwords:
            count = passwd_api_check(password)
            if count != 0:
                print(f'{bColors.WARNING}Your password {bColors.RED}{password}{bColors.WARNING} has been leaked {bColors.RED}{count}{bColors.WARNING} times{bColors.ENDC}')
            else:
                print(f'{bColors.GREEN}Your password {bColors.WARNING}{password}{bColors.GREEN} has not been compromised yet!{bColors.ENDC}')
    else:
        count = passwd_api_check(args.passwords)
        if count != 0:
            print(
                f'{bColors.WARNING}Your password {bColors.RED}{args.passwords}{bColors.WARNING} has been leaked {bColors.RED}{count}{bColors.WARNING} times{bColors.ENDC}')
        else:
            print(f'{bColors.GREEN}Your password {bColors.WARNING}{args.passwords}{bColors.GREEN} has not been compromised yet!{bColors.ENDC}')

if __name__ == '__main__':
    sys.exit(main())
