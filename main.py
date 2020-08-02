import requests
import hashlib
import sys
import argparse

'''
Using GET https://api.pwnedpasswords.com/range/{first 5 hash chars} the k-model allows anonymity as the full hash is not getting
out of your computer
'''
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
    parser.add_argument("-p", "--passwords", nargs='+', type=str, dest='passwords',
                        help="Insert the passwords to check separated by space")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if type(args.passwords) == list:
        for password in args.passwords:
            # print(password)
            count = passwd_api_check(password)
            if count != 0:
                print(f'Your password {password} has been leaked {count} times')
            else:
                print(f'Your password {password} has not been compromised yet!')
    else:
        count = passwd_api_check(args.passwords)
        if count != 0:
            print(f'Your password --> {args.passwords} has been leaked {count} times')
        else:
            print(f'Your password {args.passwords} has not been compromised yet!')


if __name__ == '__main__':
    sys.exit(main())
