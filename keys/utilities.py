###########################################################
# This is a code sample for the Ionic Security Inc. API,  #
# It assumes a SEP and usage v2.3 of the API              #
# The intention is to show how to interact with the API   #
# using built-in and 3rd-party libraries instead of the   #
# Ionic SDK.                                              #
#                                                         #
# This example uses Python 3.4.3 or higher.               #
# This example is best read with syntax highlighting on.  #
#                                                         #
# (c) 2017-2020 Ionic Security Inc.                       #
# Confidential and Proprietary                            #
# By using this code, I agree to the Terms & Conditions   #
#  (https://www.ionic.com/terms-of-use/) and the Privacy  #
#  Policy (https://www.ionic.com/privacy-notice/)         #
###########################################################

import base64
import os
import time
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def make_cid(device_id):
    ## Get a millisecond epoch time.
    ## Generate 32-bit nonce.
    ## Compose the string.

    # Get the current time in milliseconds since epoch and convert it to a string
    current_time_in_milliseconds = str(int(round(time.time() * 1000)))

    # Base64 encode a random 32-bit nonce. Here we will use the Operating System's ability to generate random bits.
    b64encoded_32_bit_nonce = base64.b64encode(os.urandom(4)).decode(encoding='utf-8')

    # Form the CID as the '|' separated conjunction of the 'CID' string, the device's ID, the stringified milliseconds
    # since epoch, and the nonce.
    return '|'.join(['CID', device_id, current_time_in_milliseconds, b64encoded_32_bit_nonce])


def decrypt_envelope(ionic_sep, server_response, cid):
    #######################################
    ### Handling the Key Fetch Response ###
    #######################################

    # See https://dev.ionic.com/api/device/get-key for more information on key fetch.

    key_fetch_response_body = server_response.json()

    # As a precaution, ensure that the client's CID is the same as the response's CID.
    response_cid = key_fetch_response_body['cid']
    if cid != response_cid:
        raise ValueError("The CID in the response did not match the one from the request.")

    # Base 64 decode the envelope's value.
    decoded_response_envelope_as_bytes = base64.b64decode(key_fetch_response_body['envelope'])
    # Prepare to decrypt the `envelope` contents.

    # Prepare to decrypt the `envelope` contents.

    # Obtain the initialization vector which is the first 16 bytes.
    initialization_vector_from_response_envelope = decoded_response_envelope_as_bytes[:16]

    # Obtain the data to decrypt, which are the bytes between the initialization vector and the auth tag.
    cipher_text_from_response_envelope = decoded_response_envelope_as_bytes[16:-16]

    # Obtain the tag which is the last 16 bytes.
    gcm_tag_from_response_envelope = decoded_response_envelope_as_bytes[-16:]

    # Construct a cipher to decrypt the data.
    cipher = Cipher(algorithms.AES(ionic_sep.aesCdIdcKey),
                    modes.GCM(initialization_vector_from_response_envelope,
                              gcm_tag_from_response_envelope),
                    backend=default_backend()
                    ).decryptor()

    # Set the cipher's `aad` as the value of the `cid`
    cipher.authenticate_additional_data(response_cid.encode(encoding='utf-8'))

    # Decrypt the ciphertext.
    decrypted_key_response_bytes = cipher.update(cipher_text_from_response_envelope) + cipher.finalize()
    decrypted_envelope = json.loads(decrypted_key_response_bytes.decode(encoding='utf-8'))

    return decrypted_envelope, response_cid
