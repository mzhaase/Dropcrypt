"""
ALPHA VERSION

UNTESTED! SHOULD NOT BE TRUSTED FOR 
IMPORTANT DATA!

This module provides encryption and decryption 
functions. 

Encryption is done via AES. Note that the AES 
implementation is provided by the pycrypto module. 
https://www.dlitz.net/software/pycrypto/

Copyright 2013 Mattis Zbigniew Haase

This file is part of Dropcrypt.

    Dropcrypt is free software: you can redistribute it
    and/or modify it under the terms of the GNU 
    General Public License as published by the Free 
    Software Foundation, either version 3 of the 
    License, or (at your option) any later version.

    Dropcrypt is distributed in the hope that it will be
    useful, but WITHOUT ANY WARRANTY; without 
    even the implied warranty of MERCHANTABILITY 
    or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU 
    General Public License along with Dropcrypt.  
    If not, see <http://www.gnu.org/licenses/>.
"""

import os
import random
import struct

import AES

import configuration

def encrypt (source, destination,  key):
    """  
    Encypts the file "source/filename" with AES and 
    saves it to "destination/filename". 
    
    unfortunately the pycrypto module doesnt have 
    good doc. so thanks to eli bendersky
    http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
    
    source: complete path of the source file
    
    destination: complete path of the destination file
    
    key: 32 byte string
    """
    filesize = os.path.getsize(source)
    init_vector = ''.join(chr(
            random.randint(0, 0xFF)) for i in range(16))
    encryptobject = AES.new(
            key, AES.MODE_CBC, init_vector)
    with open(source, 'rb') as sourceobj:
        with open(destination, 'wb') as destinationobj:
            destinationobj.write(
                    struct.pack('<Q', filesize))
            destinationobj.write(init_vector)
            while True:
                chunk = sourceobj.read(
                        configuration.chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                destinationobj.write(
                        encryptobject.encrypt(chunk))            
            
def decrypt (source, destination, key):
    """
    decrypts a file using AES.
    variables like encrypt
    """
    try:
        with open(destination, 'rb') as destinationobj:
            filesize = (struct.unpack('<Q', 
                   destinationobj.read(
                            struct.calcsize('Q')))[0])
            init_vector = destinationobj.read(16)
            decryptobject = AES.new(key,
                    AES.MODE_CBC, init_vector)
            with open(source, 'wb') as sourceobj:
                while True:
                    chunk = destinationobj.read(
                            configuration.chunksize)
                    if len(chunk) == 0:
                        break
                    sourceobj.write(
                            decryptobject.decrypt(chunk))
                sourceobj.truncate(filesize)
    except ValueError:
        print("couldnt read file.")
