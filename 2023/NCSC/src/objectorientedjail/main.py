#!/usr/local/bin/python3.10
import sys


def safeReadArgs():
    args = input("Args tuple: ")
    assert len(args) <= 570, "Aint that a bit too long?"
    code = compile(args, "tmp", "single")
    args = code.co_consts[0]
    assert type(args) == tuple, "What you doing?"
    return args


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

