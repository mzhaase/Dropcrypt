"""
ALPHA VERSION

UNTESTED! SHOULD NOT BE TRUSTED FOR IMPORTANT DATA!

This module provides encryption and decryption functions. 

Encryption is done via AES. Note that the AES implementation 
comes from the pycrypto module. 
https://www.dlitz.net/software/pycrypto/

Copyright 2013 Mattis Zbigniew Haase

This file is part of Dropcrypt.

    Dropcrypt is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Dropcrypt is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Dropcrypt.  If not, see <http://www.gnu.org/licenses/>.

It makes use of the pycrypto module, which is released under
public domain

It further makes use of some code snippets from 
http://eli.thegreenplace.net/programs-and-code/ which are released
under public domain
"""

import os, random, struct, configuration
from Crypto.Cipher import AES
from Crypto.Hash import MD5
def Encrypt (chunksize, key, local, dropbox):
    """  
    Encypts the file "source/filename" with AES and saves it to 
    "destination/filename". 
    
    unfortunately the pycrypto module doesnt have good doc. 
    so thanks to eli bendersky
    http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
    
    chunksize: to speed up encryption, files are seperated into 
    binary chunks of chunksze bytes, then each chunk is encrypted
    must be divisible by 16
    
    key: the AES key that should be 16,24 or 32 bytes long. 
    
    local: complete path of the source file
    
    dropbox: complete path of the destination file
    """
    filesize = os.path.getsize(local)
    init_vector= ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptobject = AES.new(key, AES.MODE_CBC, init_vector)
    with open(local, 'rb') as localobj:
        with open(dropbox, 'wb') as dropboxobj:
            dropboxobj.write(struct.pack('<Q', filesize))
            dropboxobj.write(init_vector)
            while True:
                chunk = localobj.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                dropboxobj.write(encryptobject.encrypt(chunk))
            
            
def Decrypt (chunksize, key, local, dropbox):
    """decrypts a file using AES.
    variables like encrypt
    so dropbox is for example /Dropbox/file
    """
    with open(dropbox, 'rb') as dropboxobj:
        filesize = struct.unpack('<Q', dropboxobj.read(struct.calcsize('Q')))[0]
        init_vector = dropboxobj.read(16)
        decryptobject = AES.new(key, AES.MODE_CBC, init_vector)
        with open(local, 'wb') as localobj:
            while True:
                chunk = dropboxobj.read(chunksize)
                if len(chunk) == 0:
                    break
                localobj.write(decryptobject.decrypt(chunk))
            localobj.truncate(filesize)

def Hash (path):
    """returns MD5 hash of a file, doesnt need to be secure, hence MD5"""
    hashor = MD5.new()
    chunksize=8192
    with open (path,  rb) as file:
        while True:
            chunk = file.read(chunk_size)
            if len(chunk) == 0:
                break
            hashor.update(chunk)
    return hashor.hexdigest()
