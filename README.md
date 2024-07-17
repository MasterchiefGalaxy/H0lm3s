# H0lmes

H0lmes is a password-cracking tool that supports multiple hash types and brute-force attacks.

## Features

- Supports MD5, SHA1, SHA256, NTLM, NTLMv2, and more.
- Brute force and dictionary attacks.
- Rule-based wordlist generation.

## Installation

```sh
git clone https://github.com/MasterchiefGalaxy/H0lm3s.git

cd H0lm3s

pip install -r requirements.txt

## Example Usage

Brute Force Attack:
python3 H0lmes.py <hash> -b --max-length 8


Dictionary Attack
python3 H0lmes.py <hash> -w /path/to/wordlist.txt


NTLMv2 Attack
python3 H0lmes.py <ntlmv2_hash> -w /path/to/wordlist.txt -u <user> -t <target>

Help
python3 H0lmes.py -h
