#!/bin/bash

python sign-util-v2.py -s -c data/usercert.pem -p data/userkey.pem -i data/file_to_sign.txt -m data/mime_file_output
echo "Saved signed mime file on data/mime_file_output"

echo "Verifying the mime file"
python sign-util-v2.py -v -c data/usercert.pem -a data/root.pem -m data/mime_file_output
