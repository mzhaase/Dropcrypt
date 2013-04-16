"""
ALPHA VERSION

UNTESTED! SHOULD NOT BE TRUSTED FOR 
IMPORTANT DATA!

This is the main script. Syncs files on first startup. 
Monitors changes in source and destination folders, 
and then either decrypts or encrypts the changed 
files, also moves, creates or deletes files and folders, 
so both folders stay synced. Utilizes watchdog 
module.

Copyright 2013 Mattis Zbigniew Haase

This file is part of Dropcrypt.

Dropcrypt is free software: you can redistribute it 
and/or modify it under the terms of the GNU General 
Public License as published by the Free Software 
Foundation, either version 3 of the License, or
(at your option) any later version.

Dropcrypt is distributed in the hope that it will be 
useful, but WITHOUT ANY WARRANTY; without even 
the implied warranty of MERCHANTABILITY or 
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
General Public License for more details.

You should have received a copy of the GNU General
Public License along with Dropcrypt.  If not, see 
<http://www.gnu.org/licenses/>.
    
This module utilizes the watchdog module, copyright
2010 by gora kargosh 
http://pythonhosted.org/watchdog/
See watchdog_LICENSE for further details
"""

import time
import logging
import hashlib
import os
import shutil

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import configuration
import encryption


class _Handler (FileSystemEventHandler):
    """Acts on file system events"""
    def on_created(self,  event):
        """Creates folders, files are handled through
        on_modified"""
        if (event.src_path.startswith
            (sourcepath)): 
            if event.is_directory:
                os.makedirs(event.src_path.replace
                        (sourcepath, destinationpath))
        elif (event.src_path.startswith
            (destinationpath)): 
            if event.is_directory:
                os.makedirs(event.src_path.replace
                        (destinationpath, sourcepath))
    
    def on_deleted(self,  event):
        """
        Detects and acts upon deletion events. for 
        some reason it doesnt work yet, so deleted
        files are only deleted upon restarting the script
        """
        filename = os.path.basename(event.src_path)
        if event.src_path.startswith(sourcepath): 
            path = event.src_path.replace(sourcepath, 
                    destinationpath)
            #if something in sourcefolder was changed
            if not os.path.exist(path):
                #if there is no file to be deleted
                return
            else:
                print ("deleting %s in destination" % 
                       (filename))
                os.remove(path)
        elif event.src_path.startswith(destinationpath): 
            path = event.src_path.replace(destinationpath, 
                    sourcepath)
            #if something in the destination was changed
            if not os.path.exist(path):
                #if there is no file to be deleted
                return
            else:
                print ("deleting %s in source" % 
                       (filename))
                os.remove(path)
    
    def on_modified(self, event):
        """acts upon modified files, calls encryption 
        and decryption"""
        if not event.is_directory:
            #encryption and decryption of files below
            filename = os.path.basename(event.src_path)
            if event.src_path.startswith(sourcepath): 
                #if source folder was changed
                path = event.src_path.replace(sourcepath, 
                        destinationpath)
                if (os.path.isfile(destinationpath) and 
                        (os.path.getmtime(destinationpath) >
                        os.path.getmtime(sourcepath))): 
                    """if there already is a file with the same 
                    name in destinationfolder, and db file 
                    is younger"""
                    print "file already up to date" 
                    return
                else:
                    print ("encrypting %s" % (filename))
                    encryption.encrypt(event.src_path,
                            path,  key)
            elif event.src_path.startswith(destinationpath):
                #if destinationfolder was changed
                path = event.src_path.replace(
                        destinationpath, sourcepath)
                if (os.path.isfile(sourcepath) and 
                        (os.path.getmtime(destinationpath) <
                        os.path.getmtime(sourcepath))):
                    #if there already is a file called like 
                    #this in the source folder, and source 
                    #file is younger
                    print "file already up to date"
                    return
                else:
                    print ("decrypting %s" % (filename))
                    encryption.decrypt(path, 
                            event.src_path,  key)
        else:
            return
    
    def on_moved(self,  event):
        if event.src_path.startswith(destinationpath):
            #if a file was moved on the destination
            #we replace the /home/bla/destination/ with
            #home/bla/source/
            src_path = event.src_path.replace(
                    destinationpath,  sourcepath)
            dest_path = event.dest_path.replace(
                    destinationpath,  sourcepath)
            if os.path.exists(src_path):
                #final check if the file or directory 
                #actually exists
                print ("moving %s to %s"%(src_path,
                        dest_path))
                shutil.move(src_path,  dest_path)
        elif event.src_path.startswith(sourcepath):
            #if a file was moved on /source
            src_path=event.src_path.replace(
                    sourcepath,  destinationpath)
            dest_path=event.dest_path.replace(
                    sourcepath,  destinationpath)
            if os.path.exists(src_path):
                #final check if the file or directory 
                #actually exists
                print ("moving %s to %s"%(src_path,
                        dest_path))
                shutil.move(src_path,  dest_path)
        else:
            return
          
def get_key():
    """
    gets key and hashes it a thousand times. Hashing
    is used to
    a) make sure the result is a 32 byte string, as this 
    is needed for AES and 
    b) make password more difficult to brute force if
    attacker does memory dump.
    
    Unfortunately, in reality attackers either read 
    hash from RAM and use this directly with a little
    basic programming, or just use a keylogger. 
    You should always follow this simple rule:
    
    if an attacker gains physical access, the machine
    and everything on it is corrupted, and all secrets 
    are revealed
    """
    global key
    if len(configuration.keyfile)==0:
        key = input("Please enter your password: ")
        for i in range (0, 999):
            key = hashlib.sha256(key).digest()
    else:
        with open (keypath,  'r') as keyfileobj:
            key = keyfileobj.read()
            key = key.strip()
        
def sync():
    """
    syncs two directories. called once on start.
    """
    destinationsnapshotobj = DirectorySnapshot(
            destinationpath, True)
    sourcesnapshotobj = DirectorySnapshot(
            sourcepath,  True)
    """
    diffobj is the difference between the two folders
    
    created are all the files and dirs that exist on the
    destinationfolder but not on the sourcefolder
    
    deleted are all the files and dirs that exist on the
    sourcefolder, but not the destinationfolder
    """
    diffobj = DirectorySnapshotDiff(
            sourcesnapshotobj,  destinationsnapshotobj)
    print ("Syncing %s and %s" %  (sourcepath, 
                                   destinationpath))
    for i in diffobj.dirs_created:
        if i.startswith(sourcepath):
            dest_path = i.replace(sourcepath, 
                                  destinationpath)
            if not os.path.isdir(dest_path):
                os.makedirs(dest_path)
                print ("Sync: making dir: %s" % 
                       dest_path)
        if i.startswith(destinationpath):
            src_path = i.replace(destinationpath, 
                                 sourcepath)
            if not os.path.isdir(src_path):
                os.makedirs(src_path)
                print ("Sync: making dir: %s" % 
                       src_path)
    for i in diffobj.dirs_moved:
        if i[0].startswith(sourcepath):
            src_path = i[0].replace(sourcepath, 
                                    destinationpath)
            dest_path = i[1].replace(sourcepath, 
                                  destinationpath)
            shutil.move(src_path,  dest_path)
            print ("Sync: move %s to %s" % (src_path, 
                                            dest_path))
        if i[0].startswith(destinationpath):
            src_path = i[0].replace(destinationpath, 
                                    sourcepath)
            dest_path = i[1].replace(destinationpath, 
                                     sourcepath)
            shutil.move(src_path,  dest_path)
            print ("Sync: move %s to %s" % (src_path, 
                                            dest_path))
    for i in diffobj.dirs_deleted:
        if i.startswith(sourcepath):
            dest_path = i.replace(sourcepath, 
                                  destinationpath)
            if os.path.isdir(dest_path):
                shutil.rmtree(dest_path)
        if i.startswith(destinationpath):
            src_path = i.replace(destinationpath, 
                                  sourcepath)
            if os.path.isdir(src_path):
                shutil.rmtree(src_path)
    for i in diffobj.files_created:
        if i.startswith(sourcepath):
            dest_path = i.replace(sourcepath, 
                             destinationpath)
                #final check if file really exits
            if os.path.isfile(i):
                encryption.encrypt(i, dest_path, key)
                print ("Sync: encrypting %s" % i)
        if i.startswith(destinationpath):
            src_path = i.replace(destinationpath, 
                               sourcepath)
                #final check if file really exists
            if os.path.isfile(i):
                encryption.decrypt(src_path, i, key)
                print ("Sync: decrypting %s" % i)
    for i in diffobj.files_modified:
        if i.startswith(sourcepath):
            dest_path = i.replace(sourcepath, 
                             destinationpath)
            if os.path.isfile(i):
                encryption.encrypt(i, dest_path, key)
                print ("Sync: encrypting %s" % i)
        if i.startswith(destinationpath):
            src_path = i.replace(destinationpath, 
                               sourcepath)
            if os.path.isfile(i):
                encryption.decrypt(src_path, i, key)
                print ("Sync: decrypting %s" % i)
    for i in diffobj.files_moved:
        #every entry is a tupel [source,destination]
        if i[0].startswith(sourcepath):
            src_path = i[0].replace(destinationpath, 
                               sourcepath)
            dest_path = i[1].replace(sourcepath, 
                             destinationpath)
            if os.path.isfile(src_path):
                shutil.move(src_path,  dest_path)
                print ("Sync: moving %s to %s" %(
                                             src_path,  dest_path))
        if i[0].startswith(destinationpath):
            src_path = i[0].replace(destinationpath, 
                               sourcepath)
            dest_path = i[1].replace(sourcepath, 
                             destinationpath)
            if os.path.isfile(src_path):
                shutil.move(src_path,  dest_path)
                print ("Sync: moving %s to %s" %(
                                             src_path,  dest_path))
    for i in diffobj.files_deleted:
        if i.startswith(sourcepath):
            dest_path = i.replace(sourcepath, 
                                  destinationpath)
            if os.path.isfile(dest_path):
                os.remove(dest_path)
                print ("Sync: deleting %s" % dest_path)
        if i.startswith(destinationpath):
            src_path = i.replace(destinationpath,
                                 sourcepath)
            if os.path.isfile(src_path):
                os.remove(src_path)
                print ("Sync: deleting %s" % src_path)
    print ("Syncing complete!")


def main():
    global destinationpath
    global sourcepath
    global keypath
    global version
    if not len(configuration.keyfile) == 0:
        keypath = os.path.realpath(
                configuration.keyfile)
    destinationpath = os.path.realpath(
            configuration.destination)
    sourcepath = os.path.realpath(
            configuration.source)
    version="VERSION0.1BUILD0001"
    get_key()
    sync()
    event_handler = _Handler()
    observer = Observer()
    observer.schedule(event_handler, 
            path=sourcepath, recursive=True)
    observer.schedule(event_handler, 
            path=destinationpath, recursive=True)
    observer.start()
    try:
        while 1:
            time.sleep(1)
    except keyboardInterrupt:
        observer.stop()
    observer.join()
        
if __name__ == '__main__':
    main()
