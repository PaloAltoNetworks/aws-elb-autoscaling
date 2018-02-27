#!/usr/bin/python

"""
/*****************************************************************************
 * Copyright (c) 2016, Palo Alto Networks. All rights reserved.              *
 *                                                                           *
 * This Software is the property of Palo Alto Networks. The Software and all *
 * accompanying documentation are copyrighted.                               *
 *****************************************************************************/

Copyright 2016 Palo Alto Networks

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import hashlib
import base64
import sys

def code_sha(filename):
    """
    Method to compute the SHA-256 encoding
    for the contents of the file specified by the
    filename.

    :param filename:
    :return: str
    """
    file=open(filename, 'rb')
    str=file.read()
    h=hashlib.sha256()
    h.update(str)
    hex=h.digest()
    m=base64.b64encode(hex)
    print('CodeSha256 for ' + filename + ' is:')
    print(m)

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print('Usage: ' + sys.argv[0] + ': <filename>')
        quit()

    code_sha(sys.argv[1])
