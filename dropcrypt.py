"""
ALPHA VERSION

UNTESTED! SHOULD NOT BE TRUSTED FOR IMPORTANT DATA!

This is the main script. Syncs files on first startup. Monitors 
changes in local and dropbox folders, and then either decrypts or 
encrypts the changed files, also moves, creates or deletes files 
and folders, so both folders stay synced.
Utilizes watchdog module.

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
    
This module utilizes the watchdog module, copyright 2010 by 
gora kargosh http://pythonhosted.org/watchdog/
See watchdog_LICENSE for further details
"""

import time,  configuration,  logging,  encryption,  os,  shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
class Handler (FileSystemEventHandler):
    """Acts on file system events"""
    def on_deleted(self,  event):
        return
    def on_modified(self, event):
        """Syncs both folders. encrypts and decrypts files, creates 
        folders"""
        print "modified"
        if not event.is_directory:
            #encryption and decryption of files below
            filename = os.path.basename(event.src_path)
            dropboxpath = os.path.realpath("%s%s" % (configuration.dropbox, filename))
            localpath = os.path.realpath("%s%s" % (configuration.local, filename))
            if event.src_path.startswith(os.path.realpath(configuration.local)): 
                #if local folder was changed
                if os.path.isfile(dropboxpath) and ((os.path.getmtime(dropboxpath)-os.path.getmtime(localpath)) < 0): 
                    #if there already is a file with the same name in dropboxfolder, and db file is younger
                    print "return" 
                    return
                else:
                    print "encrypt"
                    encryption.Encrypt(configuration.chunksize,  configuration.key,  localpath,  dropboxpath)
            if event.src_path.startswith(os.path.realpath(configuration.dropbox)):
                #if dropboxfolder was changed
                if os.path.isfile(localpath) and ((os.path.getmtime(dropboxpath)-os.path.getmtime(localpath)) > 0):
                    #if there already is a file called like this in the local folder, and local file is younger
                    print "return"
                    return
                else:
                    print "decrypt"
                    encryption.Decrypt(configuration.chunksize,  configuration.key,  localpath,  dropboxpath)
        else:
            return
            
    def on_moved(self,  event):
        print "moved"
        if event.src_path.startswith(os.path.realpath(configuration.dropbox)):
            #if a file was moved on the dropbox
            #we replace the /home/bla/dropbox/ with home/bla/local/
            src_path = event.src_path.replace(os.path.realpath(configuration.dropbox),  os.path.realpath(configuration.local))
            dest_path = event.dest_path.replace(os.path.realpath(configuration.dropbox),  os.path.realpath(configuration.local))
            if os.path.exists(src_path):
                #final check if the file or directory actually exists
                #shazam
                shutil.move(src_path,  dest_path)
        if event.src_path.startswith(os.path.realpath(configuration.local)):
            #if a file was moved on /local
            src_path=event.src_path.replace(os.path.realpath(configuration.local),  os.path.realpath(configuration.dropbox))
            dest_path=event.dest_path.replace(os.path.realpath(configuration.local),  os.path.realpath(configuration.dropbox))
            if os.path.exists(src_path):
                #final check if the file or directory actually exists
                #shazam
                shutil.move(src_path,  dest_path)
        else:
            return
            
def main():
    while 1:
        event_handler = Handler()
        observer = Observer()
        observer.schedule(event_handler, path=os.path.realpath(configuration.local), recursive=True)
        observer.schedule(event_handler, path=os.path.realpath(configuration.dropbox), recursive=True)
        observer.start()
        try:
            while 1:
                time.sleep(1)
        except keyboardInterrupt:
               observer.stop()
        observer.join()
        
if __name__ == '__main__':
    main()
