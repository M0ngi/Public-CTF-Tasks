#!/usr/local/bin/python3

import string
from sympy import isprime
from Crypto.Util.number import long_to_bytes
from random import randint

print('Show me what you got!')

x = int(input())
p = int(input())
assert isprime(p) and len(bin(p))>512

e = randint(1, p-1)
c = long_to_bytes(pow(x,e,p)).decode()

whitelist = list(string.printable)
blacklist = [
    "eval",
    "exec",
    "input",
    "code",
    "interact",
    "system",
    "pty",
    "sys",
    "vars",
    "__import__",
    "import",
    "__builtins__",
    "breakpoint",
    "os",
    "sh",
    " ",
    ";",
    ".",
    "x",
    "flag"
]

for x in c:
    if x not in whitelist:
        print('no')
        exit()

c = c[:38]

# I'll be a good guy & give you one comma!
if c.count(',') > 1:
    print('no')
    exit()

for elem in blacklist:
    if c.lower().find(elem) != -1:
        print('no')
        exit()

exec(c)
print(c)
print("Is that everything?!")
