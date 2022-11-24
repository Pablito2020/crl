#!/usr/bin/python
# -*- coding: utf-8 -*-
#  Csar Fdez 2022

import email
import email.parser
from optparse import OptionParser
from os.path import exists

from asn1crypto import cms, pem
from cryptography import x509
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (load_pem_public_key,
                                                          pkcs7)
from OpenSSL import crypto

#  https://github.com/pyca/cryptography/blob/1d996e598775766627649ff44507787d2e713e1d/tests/hazmat/primitives/test_pkcs7.py#L81-L84
# NO API implementation for verifying PKCS7

# Only for cleart-text signature  (no opaque)

# From command line:
# cat text2.txt  | openssl smime -sign -signer ../SSL/Certificats/client.pem -inkey ../SSL/Certificats/clientkey.pem -out text2.eml (-nocerts)
# openssl smime -verify -in text2.eml -CAfile ../SSL/Certificats/root.pem  (-certfile ../SSL/Certificats/client.pem)
# Per poder verificar s'ha de signar amb les opcions Binary i NoAttributes


def checkArguments():
    if args.sign == args.verify:
        print("Error: either, sign or verify")
        exit(0)
    if args.sign:
        if not exists(args.infile):
            print("Error: Input file to sign not exists")
            exit(0)
        if not exists(args.privatekey):
            print("Error: Private key to sign not exists")
            exit(0)
    if args.verify:
        if not exists(args.mimefile):
            print("Error: SMIME file to verify not exists")
            exit(0)


def extractPKCS7(message):
    ret = "-----BEGIN PKCS7-----\n"
    for m in message.walk():
        if m.get_content_type() == "application/x-pkcs7-signature":
            payload = m.get_payload()
            ret += payload
            ret += "-----END PKCS7-----"
    return ret


def verifyChain(cacert, cert, crl):
    try:
        store = crypto.X509Store()
        store.add_cert(cacert)
        if crl:
            store.add_crl(crl)
            store.set_flags(crypto.X509StoreFlags.CRL_CHECK)
        store_ctx = crypto.X509StoreContext(store, cert)
        store_ctx.verify_certificate()
        print("Cadena de certificació verificada")
    except Exception as e:
        print(f"Error en la verficació de la cadena de certificats. Error: {e}")

    return True


def verifySignature(message):
    clicertdata = b""
    for part in message.walk():
        if part.get_content_type() in ["application/x-pkcs7-signature"]:
            content_info = cms.ContentInfo.load(part.get_payload(decode=True))
            compressed_data = content_info["content"]
            signature = compressed_data["signer_infos"][0]["signature"].native
            try:
                clicertdata = compressed_data["certificates"][0].chosen.dump()
            except:
                continue
    try:
        pkey.verify(signature, bodytext.encode(), padding.PKCS1v15(), hashes.SHA256())
        print(
            "Signatura verificada. Encara no s'ha verificat la cadena de certificació"
        )
        return clicertdata
    except:
        print("Error en la verificació")
        exit(0)


parser = OptionParser()
parser.add_option(
    "-s",
    "--sign",
    dest="sign",
    help="Sign a text into a SMIME file",
    default=False,
    action="store_true",
)
parser.add_option(
    "-v",
    "--verify",
    dest="verify",
    help="Verifiy a SMIME file",
    default=False,
    action="store_true",
)
parser.add_option(
    "-c",
    "--certificate",
    dest="certificate",
    help="The signer certificate path (optional if included in email, put a wrong path (when verifying) if included certs want to be used)",
    default="data/user.pem",
)
parser.add_option(
    "-a",
    "--cafile",
    dest="cafile",
    help="The root certificate path",
    default="data/root.pem",
)
parser.add_option(
    "-p",
    "--privatekey",
    dest="privatekey",
    help="The signer private key path",
    default="data/userkey.pem",
)
parser.add_option(
    "-i", "--infile", dest="infile", help="The input file to sign", default="data/file_to_sign.txt"
)
parser.add_option(
    "-m",
    "--mimefile",
    dest="mimefile",
    help="The output smime file signed or verified",
    default="data/smime_output.eml",
)
parser.add_option(
    "-r",
    "--crl",
    dest="crl",
    help="The revokation list",
    default="data/crl/crlist.pem",
)

(args, _) = parser.parse_args()
checkArguments()

if args.verify:

    with open(args.mimefile, "rb") as f:
        mimedata = f.read()
    message = email.message_from_bytes(mimedata)
    bodytext = message.get_payload()[0].get_payload()

    with open(args.cafile, "rb") as f:
        cadata = f.read()
    cacert = crypto.load_certificate(crypto.FILETYPE_PEM, cadata)

    if exists(args.certificate):
        with open(args.certificate, "rb") as f:
            certdata = f.read()
        clicert = crypto.load_certificate(crypto.FILETYPE_PEM, certdata)

        pk = crypto.dump_publickey(crypto.FILETYPE_PEM, clicert.get_pubkey())
        pkey = load_pem_public_key(pk)

        verifySignature(message)
        crl = None
        if args.crl:
            with open(args.crl, "rb") as f:
                crldata = f.read()
                crl = crypto.load_crl(crypto.FILETYPE_PEM, crldata)
        verifyChain(cacert, clicert, crl)

    else:
        # Certs must be included in mail
        print("Getting cert from email content")
        pk7data = extractPKCS7(message)
        certs = pkcs7.load_pem_pkcs7_certificates(pk7data.encode())

        if len(certs) == 0:
            print(
                "ERROR: No hi ha certificats al PKCS7. Signat amb Nocerts option. No pots validar-se"
            )
            exit(0)

        pkey = certs[0].public_key()

        clicertdata = verifySignature(message)
        clicert = crypto.load_certificate(crypto.FILETYPE_ASN1, clicertdata)
        crl = None
        if args.crl:
            with open(args.crl, "rb") as f:
                crldata = f.read()
                crl = crypto.load_crl(crypto.FILETYPE_PEM, crldata)
        verifyChain(cacert, clicert, crl)

else:
    with open(args.certificate, "rb") as f:
        certdata = f.read()
    cert = x509.load_pem_x509_certificate(certdata)

    with open(args.privatekey, "rb") as f:
        keydata = f.read()

    with open(args.infile, "rb") as f:
        indata = f.read()

    key = serialization.load_pem_private_key(keydata, b"1234")
    # NoAtributes elimina de les dades a signar altres atributs: data, hora, ....
    # Binary no converteix els salts de linia
    # Sense aquestes opcions, no verifica
    # options = [pkcs7.PKCS7Options.DetachedSignature,pkcs7.PKCS7Options.NoAttributes, pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.NoCerts]
    options = [
        pkcs7.PKCS7Options.DetachedSignature,
        pkcs7.PKCS7Options.NoAttributes,
        pkcs7.PKCS7Options.Binary,
    ]

    m = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(indata)
        .add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.SMIME, options)
    )
    with open(args.mimefile, "wb") as f:
        f.write(m)
