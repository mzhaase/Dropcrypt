"""
ALPHA VERSION

UNTESTED! SHOULD NOT BE TRUSTED FOR 
IMPORTANT DATA!

This program reads the configuration file

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

"""with open ("config.ini_standard", 'r') as configobj:
    config=[]
    for line in configobj:
        config.append(line)
with open ("config.ini", 'w') as  configobj:
    for line in config:
        if line.startswith("source"):
            config[line] = ("source=%s"%sourcepath)"""

with open ("config.ini", 'r') as configobj:
    for line in configobj:
        if line.startswith == "#":
            continue
        else:
            line = line.strip()
            value = line.split("=")
            if value[0] == "source":
                source = value[1]
            if value[0] == "destination":
                destination = value[1]
            if value[0] == "keyfile":
                keyfile = value[1]
            if value[0] == "chunksize":
                chunksize = int(value[1])
            if value[0] == "last_sync":
                last_sync = float(value[1])
            if value[0] == "first_start":
                first_start = int(value[1])
