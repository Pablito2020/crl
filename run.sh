#!/bin/bash

python sign-util-v2.py -s -c data/usercert.pem -p data/userkey.pem -i data/file_to_sign.txt -m data/mime_file_output.eml
echo "Saved signed mime file on data/mime_file_output.eml"

python sign-util-v2.py -v -c data/usercert.pem -a data/root.pem -m data/mime_file_output.eml
