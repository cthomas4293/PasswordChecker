import requests

import hashlib

import sys


# hash generator for passwords: https://passwordsgenerator.net/sha1-hash-generator/

# use K anonymity which only sends first five hash char to site

# getting the api data from pwnedpasswords website and raising an error if done improperly.
def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code} check api and try again!")
    return res


# getting the list of hashes and counts of hacks from the response data
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# taking the users password, creating and splicing the hashed password
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first_5, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first_5)
    return get_password_leaks_count(response, tail)


if __name__ == '__main__':
    # gets the users passwords that are given and checks them against the database
    def main(args):
        for password in args:
            count = pwned_api_check(password)
            if count:
                print(f"{password} was found {count} times, you should probably change that!")
            else:
                print(f"{password} was NOT found, carry on!")
        return "Done!"


    main(sys.argv[1:])
