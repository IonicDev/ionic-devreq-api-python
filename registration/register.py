############################################################
# This is a code sample for the Ionic Security Inc. API,   #
# It assumes an STOKEN, UIDAUTH, and usage v2.3 of the API #
# The intention is to show how to interact with the API    #
# using builtin and 3rd-party libraries instead of the     #
# Ionic SDK.                                               #
#                                                          #
# This example uses Python 3.4.3                           #
# This example is best read with syntax highlighting on.   #
#                                                          #
# (c) 2017 Ionic Security Inc.                             #
# Confidential and Proprietary                             #
# By using this code, I agree to the Terms & Conditions    #
#  (https://www.ionic.com/terms-of-use/) and the Privacy   #
#  Policy (https://www.ionic.com/privacy-notice/)          #
# Author = jmassey/rmspeers, QA = daniel                   #
############################################################

import binascii
import base64
import json
import os
import requests
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from persistors.profile import DeviceProfile


# Generates a public/private key pair
def gen_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Encodes a public key
def encode_public_key_der(public_key):
    der_subj = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    der_b64 = base64.b64encode(der_subj).decode("utf-8")
    return der_b64


# Generates an AES key
def gen_aes_key():
    key = os.urandom(32)
    iv = os.urandom(16)
    return key, iv


# Encrypt message using AES in CTR mode
def encrypt_with_aes_ctr(message, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return ct


# Decrypt message using AES in CTR mode
def decrypt_with_aes_ctr(ct, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return pt


# Sign message with RSA-PSS
def sign_with_rsa_pss(private_key, message):
    signer = private_key.signer(
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256()
    )
    signer.update(message)
    signature = signer.finalize()
    return signature


# Encrypt message with RSA Optimal Asymmetric Encryption Padding (OAEP)
def encrypt_with_rsa_oaep(message, public_key):
    pk = serialization.load_der_public_key(
        public_key,
        backend=default_backend()
    )
    ct = pk.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return ct


# Decrypt message with RSA Optimal Asymmetric Encryption Padding (OAEP)
def decrypt_with_rsa_oaep(ciphertext, private_key):
    pt = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return pt


# Generate the JSON post body and keys
def generate_json_post(keyspace, enrollment_server_url, stoken, uidauth):
    ##################
    ### Create 'p' ###
    ##################

    # p1. Join STOKEN and UIDAUTH by comma (',') to form the Ionic token.
    ionic_token = ','.join([stoken, uidauth])
    # p2. Encode this string using standard Base64 encoding to form the value of the AUTH field.
    auth = base64.b64encode(ionic_token.encode("utf-8"))
    # p3. Generate a 3072-bit RSA public and private key pair. We'll refer to the private key as S.CD.
    private_key, public_key = gen_key_pair()
    # p4. DER encode the public key and Base64-encode the result using standard encoding.
    #     Do not include any newlines or other whitespace.
    tkresppubkderb64 = encode_public_key_der(public_key)
    # p5. Take these two values and form the JSON object
    json_object = json.dumps(
        {"TKRespPubKDERB64": tkresppubkderb64,
         "AUTH": auth.decode("utf-8")
         }
    )
    # p6. Encode this JSON object in a UTF-8 byte array.
    json_object_byte = json_object.encode("utf-8")
    # p7. Generate a random 256-bit AES key and a unique 16-byte initialization vector. We'll refer to this AES key as
    #  (cont) K.CD:KS
    aes_key_k_c_ks, iv = gen_aes_key()
    # p8. Use the AES key (K.CD:KS) to encrypt the contents of the byte array using counter mode
    json_object_ct = encrypt_with_aes_ctr(json_object_byte, aes_key_k_c_ks, iv)
    # p9. Prepend the initialization vector to the resulting cipher text and Base64 encode the result using standard
    #     encoding.
    p = base64.b64encode(iv+json_object_ct)

    ##################
    ### Create 's' ###
    ##################

    # Fetch the Key Server Public Key and decode it(kspk)
    kspk = requests.get("{}/keyspace/{}/pubkey".format(enrollment_server_url, keyspace))
    if kspk.status_code != 200:
        raise Exception("Error fetching the public key, check the enrollment_server_url and keyspace provided.")
    decoded_kspk = base64.b64decode(kspk.text)
    # s1. Encrypt the AES key (K.CD:KS) using the public key of the key server using the OAEP padding scheme with SHA-1 as
    #     defined in PKCS #1.
    kspk_ciphertext = encrypt_with_rsa_oaep(aes_key_k_c_ks, decoded_kspk)
    # s2. Encode the result with standard Base64 encoding. There should be no line breaks.
    s = base64.b64encode(kspk_ciphertext)

    ##################
    ### Create 'g' ###
    ##################

    # g1. Sign the p value using the generated private key (S.CD). This should be done using PSS and SHA-256 as defined in
    #     PKCS #1 with a salt length of 32 bytes.
    signature = sign_with_rsa_pss(private_key, p)
    # g2. Encode the result with standard Base64 encoding. There should be no line breaks.
    g = base64.b64encode(signature)

    ############################################################
    ### Create the post data using k (keyspace), p, s, and g ###
    ############################################################

    post_data = json.dumps(
        {
            "k": keyspace,
            "p": p.decode("utf-8"),
            "s": s.decode("utf-8"),
            "g": g.decode("utf-8")
         }
    )
    return post_data, aes_key_k_c_ks, private_key


# Decrypt SEPAESK key
def decrypt_ks_key(sepaesk, aes_key_k_c_ks):
    iv_cipher = base64.b64decode(sepaesk)
    iv = iv_cipher[:16]
    cipher = iv_cipher[16:]
    pt = decrypt_with_aes_ctr(cipher, aes_key_k_c_ks, iv)
    return binascii.hexlify(pt)


# Decrypt SEPAESK-IDC key
def decrypt_idc_key(sepaesk_idc, private_key):
    key = decrypt_with_rsa_oaep(base64.b64decode(sepaesk_idc), private_key)
    return binascii.hexlify(key)


# Perform the createDevice() equivalent
def create_device(api_url, keyspace, enrollment_server_url, stoken, uidauth):
    # Generate the request body
    post_data, aes_key_k_c_ks, private_key = generate_json_post(keyspace, enrollment_server_url, stoken, uidauth)

    # The X-Conversation-ID header should be added using a random UUID.
    x_conversation_id = str(uuid.uuid4())
    headers = {"Content-Type":"application/json", "X-Conversation-ID": x_conversation_id}
    register_api_url = api_url+ "/v2.3/register/%s" % keyspace
    r = requests.post(register_api_url, data=post_data, headers=headers)
    assert r.status_code == 200

    #######################################
    ### Registration has been completed ###
    ###  r contains the API's response  ###
    #######################################

    device_id = r.json()["deviceID"]
    sep_cd_idc = decrypt_idc_key(r.json()["SEPAESK-IDC"], private_key)
    sep_cd_ks = decrypt_ks_key(r.json()["SEPAESK"], aes_key_k_c_ks)

    profile = DeviceProfile()
    profile.deviceId = device_id
    profile.server = api_url
    profile.set_keys_from_hex_strings(sep_cd_idc, sep_cd_ks)
    profile.validate()

    return profile
