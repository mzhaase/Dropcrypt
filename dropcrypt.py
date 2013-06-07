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
        if event.src_path.startswith(sourcepath):
            if event.is_directory:
                os.makedirs(event.src_path.replace
                        (sourcepath, destinationpath))
        elif event.src_path.startswith(
                destinationpath): 
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
            if not os.path.exists(path):
                #if there is no file to be deleted
                return
            else:
                print ("deleting %s in destination" % 
                       (filename))
                os.remove(path)
        elif event.src_path.startswith(destinationpath): 
            path = event.src_path.replace(
                    destinationpath, sourcepath)
            #if something in the destination was changed
            if not os.path.exists(path):
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
            filename = os.path.basename(
                    event.src_path)
            if event.src_path.startswith(sourcepath): 
                #if source folder was changed
                path = event.src_path.replace(
                        sourcepath, destinationpath)
                if (os.path.isfile(destinationpath) and 
                        (os.path.getmtime(destinationpath) >
                        os.path.getmtime(sourcepath))): 
                    # if there already is a file with the same 
                    # name in destinationfolder, and db file 
                    # is younger
                    print "file already up to date" 
                    return
                else:
                    print ("encrypting %s" % (filename))
                    encryption.encrypt(
                            event.src_path, path,  key)
            elif event.src_path.startswith(
                    destinationpath):
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
            src_path = event.src_path.replace(
                    sourcepath,  destinationpath)
            dest_path = event.dest_path.replace(
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
        key = input(
                "Please enter your password: ")
        for i in range (0, 999):
            key = hashlib.sha256(key).digest()
    else:
        with open (keypath,  'r') as keyfileobj:
            key = keyfileobj.read()
            key = key.strip()
        for i in range (0, 999):
            key = hashlib.sha256(key).digest()
        
def sync():
    """
    syncs two directories. called once on start.
    the code is inspired by
    https://ssscripting.wordpress.com/2011/11/01/python-directory-synchronization/
    """
    start = time.time()
    def _dirtree(path):
        """
        creates list of dirs and files in source and 
        destination
        """
        returndirs = []
        returnfiles = []
        
        for root, dirs, files in os.walk(path):
            for _dir in dirs:
                abs_dir = os.path.join(root, _dir)
                returndirs.append(
                        [abs_dir, 
                        os.path.relpath(abs_dir, path)]
                )
            for _file in files:
                abs_f = os.path.join(root, _file)
                returnfiles.append(
                        [abs_f, 
                        os.path.relpath(abs_f, path)]
                )
        return (returndirs, returnfiles)

    src_dirs, src_files  = _dirtree(sourcepath)
    dest_dirs, dest_files = _dirtree(destinationpath)

    for src_dir in src_dirs:
        try:
            rel_path = src_dir[1]
            equivalent_dest_dir = filter(
                lambda e:e[1] == rel_path, dest_dirs)
            dest_path = os.path.join(
                    destinationpath, rel_path)
            src_atime = os.path.getatime(src_dir[0])
            if len(equivalent_dest_dir) == 0:
                # if dir is in source but not in destination
                if src_atime > configuration.last_sync:
                    # if source dir was created after last sync
                    os.makedirs(dest_path)
                    print ("creating %s" % dest_path)
                elif src_atime < configuration.last_sync:
                    # if dest dir was deleted after last sync
                    shutil.rmtree(src_dir[0])
                    print ("deleting %s" % src_dir[0])
        except (IOError, ValueError, OSError):
            print ("some kind of error occured")
    for dest_dir in dest_dirs:
        try:
            rel_path = dest_dir[1]
            equivalent_src_dir = filter(
                lambda e:e[1] == rel_path,src_dirs)
            src_path = os.path.join(
                    sourcepath,rel_path)
            dest_atime = os.path.getatime(dest_dir[0])
            if len(equivalent_src_dir) == 0:
                # if dir is in destination but not source
                if dest_atime > configuration.last_sync:
                    # if destination dir was created after last
                    # sync
                    os.makedirs(src_path)
                    print ("creating %s" % src_path)
                elif dest_atime < configuration.last_sync:
                    # if source dir was deleted after last sync
                    shutil.rmtree(dest_dir[0])
                    print ("deleting %s" % dest_dir[0])
        except (IOError, ValueError, OSError):
            print ("some kind of error occured")
    for src_file in src_files:
        try:
            rel_path = src_file[1]
            equivalent_dest_file = filter(
                    lambda e:e[1] == rel_path,dest_files)
            dest_path = os.path.join(
                    destinationpath,rel_path)
            src_atime = os.path.getatime(src_file[0])
            if os.path.isfile(dest_path):
                dest_atime = os.path.getatime(dest_path)
            if len(equivalent_dest_file) == 0:
                # if the file is in source but not in dest
                if src_atime > configuration.last_sync + 300:
                   # if sourcefile is younger than last sync
                    encryption.encrypt(
                            src_file[0],dest_path, key)
                    print ("encrypting %s" % src_file[0])
                elif src_atime +300 < configuration.last_sync:
                   # if sourcefile is older than last sync
                    os.unlink(src_file[0])
                    print ("deleting %s" % src_file[0])
            elif dest_atime + 300 < src_atime:
                # if file is in dest AND source, and source is
                # younger
                encryption.encrypt(
                        src_file[0], dest_path, key)
                print ("encrypting %s" % src_file[0])
            elif dest_atime > src_atime + 300:
                # if file is in dest AND source, and dest is 
                # younger
                encryption.decrypt(
                        src_file[0], dest_path, key)
                print ("decrypting %s" % dest_path)
        except (IOError, ValueError, OSError):
            print ("some kind of error occured")
    for dest_file in dest_files:
        try:
            rel_path = dest_file[1]
            equivalent_src_file = filter(
                    lambda e:e[1] == rel_path,src_files)
            src_path = os.path.join(
                    sourcepath,rel_path)
            if os.path.isfile(src_path):
                src_atime = os.path.getatime(src_path)
            dest_atime = os.path.getatime(dest_file[0])
            if len(equivalent_src_file) == 0:
                # if file is in destination but not in source
                if dest_atime > configuration.last_sync + 300:
                    # if file was created after last sync
                    encryption.decrypt(
                            src_path, dest_file[0], key)
                    print ("decrypting %s" % dest_file[0])
                elif dest_atime + 300 < configuration.last_sync:
                    # if file was created before last sync
                    os.unlink(dest_file[0])
                    print ("deleting %s" % dest_file[0])
            elif src_atime + 300 < dest_atime:
                # if file exists in source AND dest and dest
                # is younger
                encryption.decrypt(
                        src_path, dest_file[0], key)
                print ("decrypting %s" % dest_file[0])
            elif src_atime > dest_atime + 300:
                # if file exists in source AND dest and
                # source is younger
                encryption.encrypt(
                        src_path, dest_file[0], key)
                print ("encrypting %s" % src_path)
        except (IOError, ValueError, OSError):
            print ("some kind of error occured")
    timetaken = time.time()-start
    with open("config.ini",  'r') as configobj:
        with open("config.ini_", 'w') as tempobj:
            for line in configobj:
                if not line.startswith("last_sync"):
                    tempobj.write(line)
                elif line.startswith("last_sync"):
                    print("yep")
                    tempobj.write(
                            "last_sync=%f\n" % float(time.time()-timetaken))
    try:
        os.rename("config.ini_", "config.ini")
        print ("config updated")
    except:
        print("error showing the errormessage.") 
        print("Hah. Gotcha. In reality, this is just some error")
        print("that shouldnt happen, but probably will in your")
        print("weird excuse of an machine. Be proud. ")    
        print("Oh your configfile might be missing. In which ")    
        print("case this software wont work. Yeah, there is that.")


def main():
    """
    main function, initializes program and calls sub
    programs
    """
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
    version = "VERSION0.1BUILD0001"
    get_key()
    print("key hashed")
    sync()
    print("sync completed")
    print ("starting watchdog dont close this window")
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
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
        
if __name__ == '__main__':
    main()
