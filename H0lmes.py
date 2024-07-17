import argparse
import hashlib
import itertools
import string
from Crypto.Hash import MD4
from passlib.hash import nthash, bcrypt
import binascii
import hmac
from tqdm import tqdm
from argon2 import PasswordHasher

ascii_art = r"""
HHHHHHHHH     HHHHHHHHH     000000000     lllllll                          333333333333333
H:::::::H     H:::::::H   00:::::::::00   l:::::l                         3:::::::::::::::33
H:::::::H     H:::::::H 00:::::::::::::00 l:::::l                         3::::::33333::::::3
HH::::::H     H::::::HH0:::::::000:::::::0l:::::l                         3333333     3:::::3
  H:::::H     H:::::H  0::::::0   0::::::0 l::::l    mmmmmmm    mmmmmmm               3:::::3    ssssssssss
  H:::::H     H:::::H  0:::::0     0:::::0 l::::l  mm:::::::m  m:::::::mm             3:::::3  ss::::::::::s
  H::::::HHHHH::::::H  0:::::0     0:::::0 l::::l m::::::::::mm::::::::::m    33333333:::::3 ss:::::::::::::s
  H:::::::::::::::::H  0:::::0 000 0:::::0 l::::l m::::::::::::::::::::::m    3:::::::::::3  s::::::ssss:::::s
  H:::::::::::::::::H  0:::::0 000 0:::::0 l::::l m:::::mmm::::::mmm:::::m    33333333:::::3  s:::::s  ssssss
  H::::::HHHHH::::::H  0:::::0     0:::::0 l::::l m::::m   m::::m   m::::m            3:::::3   s::::::s
  H:::::H     H:::::H  0:::::0     0:::::0 l::::l m::::m   m::::m   m::::m            3:::::3      s::::::s
  H:::::H     H:::::H  0::::::0   0::::::0 l::::l m::::m   m::::m   m::::m            3:::::3ssssss   s:::::s
HH::::::H     H::::::HH0:::::::000:::::::0l::::::lm::::m   m::::m   m::::m3333333     3:::::3s:::::ssss::::::s
H:::::::H     H:::::::H 00:::::::::::::00 l::::::lm::::m   m::::m   m::::m3::::::33333::::::3s::::::::::::::s
H:::::::H     H:::::::H   00:::::::::00   l::::::lm::::m   m::::m   m::::m3:::::::::::::::33  s:::::::::::ss
HHHHHHHHH     HHHHHHHHH     000000000     llllllllmmmmmm   mmmmmm   mmmmmm 333333333333333     sssssssssss

By: 5h3ph3rd
"""

def identify_hash(hash_value):
    hash_lengths = {
        32: ['md5', 'md4', 'ntlm'],
        40: ['sha1'],
        56: ['sha224'],
        60: ['bcrypt'],
        64: ['sha256'],
        96: ['sha384'],
        128: ['sha512'],
        32*2: ['ntlmv2']  # NTLMv2 is 32 bytes in hex (64 characters)
    }

    possible_hashes = hash_lengths.get(len(hash_value), [])
    return possible_hashes if possible_hashes else ['Unknown']

def get_hash_function(hash_type):
    if hash_type == 'md4':
        return lambda x: MD4.new(x).hexdigest()
    elif hash_type == 'ntlm':
        return nthash.hash
    elif hash_type == 'bcrypt':
        return lambda x: bcrypt.hashpw(x, bcrypt.gensalt()).decode()
    elif hash_type == 'argon2':
        ph = PasswordHasher()
        return lambda x: ph.hash(x)
    else:
        return lambda x: getattr(hashlib, hash_type)(x).hexdigest()

def crack_ntlmv2(hash_value, wordlist, user, target):
    with open(wordlist, 'rb') as f:
        for line in tqdm(f, desc="Cracking Progress"):
            try:
                password = line.strip().decode('utf-8', errors='ignore')
                ntlm_hash = nthash.hash(password)
                response_hash = hmac.new(ntlm_hash.encode('utf-8'), (user + target).encode('utf-8'), hashlib.md5).hexdigest()
                if response_hash == hash_value:
                    return password
            except UnicodeDecodeError:
                continue
    return None

def crack_hash(hash_type, hash_value, wordlist, user=None, target=None):
    if hash_type == 'ntlmv2':
        return crack_ntlmv2(hash_value, wordlist, user, target)

    hash_func = get_hash_function(hash_type)

    with open(wordlist, 'rb') as f:
        lines = f.readlines()

    for line in tqdm(lines, desc="Cracking Progress"):
        try:
            word = line.strip().decode('utf-8', errors='ignore')
            if hash_func(word.encode()) == hash_value:
                return word
        except UnicodeDecodeError:
            continue
    return None

def brute_force_crack(hash_type, hash_value, min_length=1, max_length=8, charset=string.ascii_letters + string.digits):
    hash_func = get_hash_function(hash_type)

    for length in range(min_length, max_length + 1):
        for word in tqdm(itertools.product(charset, repeat=length), desc=f"Brute Force Progress (Length: {length})", total=len(charset)**length):
            word = ''.join(word)
            if hash_func(word.encode()) == hash_value:
                return word
    return None

def transform_word(word):
    transformations = [
        lambda x: x.lower(),
        lambda x: x.upper(),
        lambda x: x.capitalize(),
        lambda x: x.replace('a', '@').replace('s', '$').replace('o', '0').replace('i', '1'),
        lambda x: x + '123',
    ]

    transformed_words = set()
    for transform in transformations:
        transformed_words.add(transform(word))

    return transformed_words

def generate_rules_based_wordlist(wordlist):
    transformed_list = set()
    with open(wordlist, 'r') as f:
        for line in f:
            word = line.strip()
            transformed_list.update(transform_word(word))

    return list(transformed_list)

def main():
    print(ascii_art)

    parser = argparse.ArgumentParser(description="H0lmes: Password cracking tool")
    parser.add_argument('hash', type=str, help='The hash to crack')
    parser.add_argument('-w', '--wordlist', type=str, help='Path to the wordlist file')
    parser.add_argument('-u', '--user', type=str, help='User for NTLMv2')
    parser.add_argument('-t', '--target', type=str, help='Target for NTLMv2')
    parser.add_argument('-b', '--brute', action='store_true', help='Enable brute force cracking')
    parser.add_argument('--charset', type=str, default=string.ascii_letters + string.digits, help='Character set for brute force')
    parser.add_argument('--min-length', type=int, default=1, help='Minimum length for brute force')
    parser.add_argument('--max-length', type=int, default=8, help='Maximum length for brute force')

    args = parser.parse_args()

    print("Determining hash type...")

    possible_hash_types = identify_hash(args.hash)
    if 'Unknown' in possible_hash_types:
        print("Unsupported or unknown hash type.")
        return

    hash_type = possible_hash_types[0]
    print(f"Identified hash type: {hash_type}")
    print("Please wait while we crack your hash...")

    for hash_type in possible_hash_types:
        print(f"Attempting to crack hash using {hash_type}...")
        if args.wordlist:
            result = crack_hash(hash_type, args.hash, args.wordlist, args.user, args.target)
            if result:
                print(f"Password found using {hash_type}: {result}")
                return
        elif args.brute:
            print("Starting brute force attack...")
            result = brute_force_crack(hash_type, args.hash, args.min_length, args.max_length, args.charset)
            if result:
                print(f"Password found using brute force with {hash_type}: {result}")
                return

    print("Password not found.")

if __name__ == "__main__":
    main()
