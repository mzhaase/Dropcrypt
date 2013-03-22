"""
ALPHA VERSION

UNTESTED! SHOULD NOT BE TRUSTED FOR IMPORTANT DATA!

This is the configuration file for Dropcrypt.  

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
"""
#
#YOU MUST CONFIGURE THE FOLLOWING
#
#please specify your local folder in which the UNENCRYPTED
#files should be stored. this folder CANNOT be inside your 
#dropbox folder. 
local = "./local/"

#please specify the folder in which the ENCRYPTED files should
#be stored. This is usually your dropbox folder
dropbox = "./dropbox/"

#please choose a key. note: this program is not meant to protect
#local files. everyone with access to your computer can get the
#key out of ram anyway. hence why you have to choose it here.
key = "1234567890123456"
#
#------------------------------------------------------------------------------------------------
#
#OPTIONS THAT COULD BE HELPFUL
#


#
#------------------------------------------------------------------------------------------------
#
#OPTIONS YOU SHOULD LEAVE ALONE
#
#chunksize must be divisible by 16
chunksize = 16
