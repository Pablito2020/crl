#!/bin/bash

echo "======== SHOULD BE GOOD, CERTIFICATE NOT IN CRL ========"
python sign-util-v2.py -s -c data/usercert.pem -p data/userkey.pem -i data/file_to_sign.txt -m data/mime_file_output.eml
python sign-util-v2.py -v -c data/usercert.pem -a data/root.pem -m data/mime_file_output.eml -r data/crl/crlist.pem

echo ""

echo "======== SHOULD BE GOOD, WE DON'T CHECK CRL ========"
python sign-util-v2.py -v -c data/revokatedclientcert.pem -a data/root.pem -m data/mime_file_output_r.eml

echo ""

echo "======== SHOULD BE BAD, CERTIFICATE INSIDE CRL ========"
python sign-util-v2.py -s -c data/revokatedclientcert.pem -p data/revokatedclientkey.pem -i data/file_to_sign.txt -m data/mime_file_output_r.eml
python sign-util-v2.py -v -c data/revokatedclientcert.pem -a data/root.pem -m data/mime_file_output_r.eml -r data/crl/crlist.pem
