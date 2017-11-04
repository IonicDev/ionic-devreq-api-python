##########################################################
# This is a code sample for the Ionic Security Inc. API,  #
# It assumes a SEP and usage v2.3 of the API              #
# The intention is to show how to interact with the API   #
# using built-in and 3rd-party libraries instead of the   #
# Ionic SDK.                                              #
#                                                         #
# This example uses Python 3.4.3                          #
# This example is best read with syntax highlighting on.  #
#                                                         #
# (c) 2017 Ionic Security Inc.                            #
# Confidential and Proprietary                            #
# By using this code, I agree to the Terms & Conditions   #
#  (https://www.ionic.com/terms-of-use/) and the Privacy  #
#  Policy (https://www.ionic.com/privacy-notice/)         #
# Author = daniel, QA = jmassey                           #
###########################################################

import base64
import binascii
import hmac
import hashlib
import json
import os
import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import keys.utilities as utilities

####################################################
### Requires a Device Secure Enrollment Profile  ###
####################################################


def fetch_key_request(ionic_sep, protection_keys, external_id=None, send_full_hfp=False):
    # 1. Build up the request
    key_fetch_data = {
        "protection-keys": protection_keys
    }
    if external_id is not None:
        if not isinstance(external_id, (str, list)):
            raise TypeError
        if isinstance(external_id, str):
            external_id = [external_id]
        protection_key_queries = {"protection-key-queries": {}}
        for k, i in enumerate(external_id):
            protection_key_queries["protection-key-queries"]["qref" + str(k)] = {"ionic-external-id": i}
        key_fetch_data.update(protection_key_queries)

    # 2. Construct or obtain a cached copy of the needed meta data.
    ## - This will include the hfphash.
    ## - If an update is needed, this should include the full hfp.
    # NOTE: This represents the minimum contents, and it assumes that the device's fingerprint is saved in IDC and has not changed locally.
    # Therefore we can send only the `hfphash`.
    # Here the `hfphash` is obtained from the `ionic_sep` dict:
    hfphash = ionic_sep.get_hfp_hash()

    # 3. Compose the `meta` and `data`. Serialize the JSON object containing `meta` and `data` as fields to a byte array
    #    representation encoded using UTF-8.
    # Construct the `envelope` contents: { "meta": <>, "data": <> }
    if send_full_hfp:
        hfp = ionic_sep.get_hfp()
        # this will convert the hfp from dict to string. The server expects a string and not a json object
        if isinstance(hfp, dict):
            hfp = json.dumps(hfp)
        envelope_contents = {
            "meta": {
                "hfphash": hfphash,
                "hfp": hfp
            },
            "data": key_fetch_data
        }
    else:
        envelope_contents = {
            "meta": {
                "hfphash": hfphash
            },
            "data": key_fetch_data
        }

    # Serialize the `envelope` contents to a byte array containing the UTF-8 encoding of the contents.
    serialized_envelope_contents = json.dumps(envelope_contents).encode(encoding='utf-8')

    # 4. Compose a Conversation ID string in a UTF-8 encoded byte array.
    cid = utilities.make_cid(ionic_sep.deviceId)

    # 5. Encrypt the array of JSON bytes using AES-256 GCM. AES-256 GCM encryption requires a key, an initialization
    #    vector, and auth data (also called AAD). Encryption returns both encrypted bytes and an auth tag.
    ## - Use the SEP.CD:IDC value as the key.
    ## - Create a 16-byte initialization vector of random bytes.
    ## - Set the authenticated data (AAD) to be the Conversation ID byte array.
    ## - Encrypt the JSON byte array.

    # Create a 16-byte initialization vector of random bytes.
    initialization_vector = os.urandom(16)

    # Create an AES-GCM cipher using the SEP.CD:IDC as the key and the 16-byte initialization vector.
    cipher = Cipher(algorithms.AES(ionic_sep.aesCdIdcKey),
                    modes.GCM(initialization_vector),
                    backend=default_backend()
                    ).encryptor()

    # Set the authenticated data (AAD) to be the Conversation ID byte array.
    cipher.authenticate_additional_data(cid.encode(encoding='utf-8'))

    # Encrypt the JSON byte array.
    cipher_text = cipher.update(serialized_envelope_contents) + cipher.finalize()

    # 6. Combine the initialization vector, the encrypted JSON, and the auth tag.
    ## - Prepend the resulting cipher text bytes with the initialization vector.
    ## - Append the auth tag to the resulting cipher text.
    iv_cipher_text_aad = b''.join([initialization_vector, cipher_text, cipher.tag])

    # 7. Encode the results of the previous step as a single array of bytes using Base64.
    b64encoded_iv_cipher_text_aad_as_bytes = base64.b64encode(iv_cipher_text_aad)
    b64encoded_iv_cipher_text_aad_as_string = b64encoded_iv_cipher_text_aad_as_bytes.decode(encoding='utf-8')

    # 8. Compose a JSON representation containing the resulting Base64-encoded string as the value
    #    of the envelope field and the Conversation ID string as the value of the cid field.
    # This representation should use UTF-8 encoding.
    key_fetch_request_body = {
        "cid": cid,
        "envelope": b64encoded_iv_cipher_text_aad_as_string
    }

    # Send the request to Ionic as an HTTP POST with JSON data to https://{api_base}/v2.3/keys/fetch
    key_fetch_response = requests.post('%s/v2.3/keys/fetch' % ionic_sep.server,
                                       data=json.dumps(key_fetch_request_body),
                                       headers={'Content-Type': 'application/json'})

    # Assume the response from Ionic is a successful 200 and that we have received keys for the provided key tags.
    assert (key_fetch_response.status_code == 200) or (key_fetch_response.status_code == 401)

    return key_fetch_response, cid


def decrypt_envelope(ionic_sep, key_fetch_response, cid):
    #######################################
    ### Handling the Key Fetch Response ###
    #######################################

    key_fetch_response_body = key_fetch_response.json()

    # As a precaution, ensure that the client's CID is the same as the response's CID.
    response_cid = key_fetch_response_body['cid']
    assert cid == response_cid

    # Base 64 decode the envelope's value.
    decoded_key_fetch_response_envelope_as_bytes = base64.b64decode(key_fetch_response_body['envelope'])

    # Prepare to decrypt the `envelope` contents.

    # Obtain the initialization vector which is the first 16 bytes.
    initialization_vector_from_response_envelope = decoded_key_fetch_response_envelope_as_bytes[:16]

    # Obtain the data to decrypt which is the bytes between the initializaiton vector and the tag.
    cipher_text_from_response_envelope = decoded_key_fetch_response_envelope_as_bytes[16:-16]

    # Obtain the tag which is the last 16 bytes.
    gcm_tag_from_response_envelope = decoded_key_fetch_response_envelope_as_bytes[-16:]

    # Construct a cipher to decrypt the data.
    cipher = Cipher(algorithms.AES(ionic_sep.aesCdIdcKey),
                    modes.GCM(initialization_vector_from_response_envelope,
                              gcm_tag_from_response_envelope),
                    backend=default_backend()
                    ).decryptor()

    # Set the cipher's `aad` as the value of the `cid`.
    cipher.authenticate_additional_data(response_cid.encode(encoding='utf-8'))

    # Decrypt the ciphertext.
    decrypted_key_response_bytes = cipher.update(cipher_text_from_response_envelope) + cipher.finalize()
    decrypted_envelope = json.loads(decrypted_key_response_bytes.decode(encoding='utf-8'))

    return decrypted_envelope


def fetch_keys(ionic_sep, protection_keys, external_ids=None):
    ##########################################
    ### Constructing the Key Fetch Request ###
    ##########################################
    example_key_fetch_body = """
    {
      "cid": "CID|MfyG..A.ec095b70-c1d0-4ac0-9d0f-2cafa82b8a1f|1487622171374|1487622171374|5bFnTQ==",
      "envelope": {
        "meta": {
          "hfphash": "aa0e43bfd6e7d5a9ea88e72d38d12df50bfb36e66710a5bb8417d8fb48230fc9"
        },
        "data": {
          "protection-keys": [
            "MfygGadsg23",
            "MfygGP34erq"
          ]
        }
      }
    }
    """

    # 1. Construct the request data.
    key_fetch_response, cid = fetch_key_request(ionic_sep, protection_keys, external_id=external_ids)

    decrypted_envelope, _ = utilities.decrypt_envelope(ionic_sep, key_fetch_response, cid)

    # NOTE: It is possible that an error occurred, perhaps the time recorded by the client and that held by the server differ
    # more than +/-5 minutes or the device needs to send its entire fingerprint (`hfp`).
    # Please see the errors and error handling for more information.
    if decrypted_envelope.get('error'):
        print("\nA partial error has occurred. The following is the response from the server:")
        print(decrypted_envelope["error"])
        if decrypted_envelope["error"]["code"] == 4001:
            print(
                "\nIn this scenario, the hfphash is not recognized by the server. A new request will be generated with "
                "the full HFP included.")

            key_fetch_response, cid = fetch_key_request(ionic_sep, protection_keys, send_full_hfp=True)
            decrypted_envelope = decrypt_envelope(ionic_sep, key_fetch_response, cid)

    # Pull out any query results as well to return:
    query_results = decrypted_envelope['data'].get('query-results')

    # Now we have a dict containing the keys.
    example_key_fetch_response_keys = """
            {
              "cid": "CID|MfyG..A.ec095b70-c1d0-4ac0-9d0f-2cafa82b8a1f|1487622171374|1487622171374|5bFnTQ==",
              "envelope": {
                "data": {
                  "protection-keys": [
                    {
                      "id": "MfygGadsg23",
                      "key":"d913c4282fbd1a8968bd8d70994d2f4ea19c983c29242b9473b9467ea48195ceb4782c76e46f48c62cf044a11a438e23280aed1cbd0e2a159e7f38f23c68132f",
                      "cattrs": "{\"attr1\":[\"attr1val1\",\"attr1val2\"],\"attr2\":[\"attr2val1\"]}",
                      "csig": "oRPW3N3a4CKdwhV00XlJKLZ/4GTjWJ+V4MJh2Ry3Z5g="
                    },
                    {
                      "id": "MfygGP34erq",
                      "key":"8c79b8bf3233709046614f09985246fa8150761539408dcb636f023a406c10b7058a3adc57cc8db39b96fdeabebc9458828eba63900f89431ba12b23f2ae718b",
                      "cattrs":"{\"attr1\":[\"attr1val1\",\"attr1val2\"],\"attr2\":[\"attr2val1\"],\"ionic-protected-attr\":[\"asdg2rezx...\"]}",
                      "csig": "F00RIKIAe/P4e6/MuuiFvY2M3STeMijAa48WTofD2O8="
                    }
                  ]
                }
              }
            }
            """

    # To decrypt each returned data key:
    ## 1. Decode the contents of the `key` field using hex. The cipher text contains the initialization vector,
    ##    the data, and the auth tag.
    ## 2. Form the additional authenticated data as the conversation ID of the request,
    ##    the `keytag`, and if present the `csig` separated by colons `:` as UTF-8
    ##    bytes (either `CID|Mfyg...|..b4:MfygGadsg23` or in this case
    ##    `CID|Mfyg...|..b4:MfygGadsg23:oRPW...5g=` .
    ## 3. Decrypt the cipher text using 256-bit AES-GCM.
    ### - The initialization vector is the first 16 bytes of the decoded bytes.
    ### - The auth tag is the last 16 bytes of the decoded bytes.
    ### - The key is the `SEP.CD:KS` key.
    ### - The additional authenticated data is the byte string formed in the previous step.
    ## The result is a 256-bit AES key in raw bytes.

    decrypted_keys = {}  # simple storage for the data we're decrypting from the response
    for key in decrypted_envelope['data']['protection-keys']:
        key_id = key['id']
        hex_encoded_encrypted_key = key['key']
        encrypted_key_bytes = binascii.unhexlify(hex_encoded_encrypted_key)
        aad_pieces = [cid, key_id]
        if key.get('csig'):
            aad_pieces += [key['csig']]
        aad = ':'.join(aad_pieces)
        key_iv = encrypted_key_bytes[:16]
        key_data = encrypted_key_bytes[16:-16]
        key_auth_tag = encrypted_key_bytes[-16:]
        cipher = Cipher(algorithms.AES(ionic_sep.aesCdEiKey),
                        modes.GCM(key_iv,
                                  key_auth_tag),
                        backend=default_backend()
                        ).decryptor()
        cipher.authenticate_additional_data(aad.encode(encoding='utf-8'))
        decrypted_key_bytes = cipher.update(key_data) + cipher.finalize()
        decrypted_keys[key_id] = {'bytes': decrypted_key_bytes}

        # Add obligations if they were received:
        if key.get('obligations'):
            decrypted_keys[key_id]['obligations'] = key.get('obligations')

        #####################################
        # Verifying the Attribute Signature #
        #####################################
        # To verify the attribute signature:
        # 1. Compute a HMAC-SHA-256 over the client attributes `cattrs` as a UTF-8 encoded JSON string (as present in the
        #    returned JSON) using the decrypted data key.
        # 2. Decode the `csig` field using Base64.
        # 3. Compare the raw bytes of the previous two steps expecting that they are the same.

        if key.get('csig'):
            # 1. Compute a HMAC-SHA-256 over the client attributes cattrs as a UTF-8 encoded JSON string (as present in the
            #    returned JSON) using the decrypted data key.
            csigHMACer = hmac.new(decrypted_key_bytes, msg=key['cattrs'].encode(encoding='utf-8'), digestmod=hashlib.sha256)
            key_cattrs_hmac_256_bytes = csigHMACer.digest()

            # 2. Decode the `csig` field using Base64.
            decoded_csig = base64.b64decode(key['csig'])

            # 3. Compare the raw bytes of the previous two steps expecting that they are the same
            assert hmac.compare_digest(decoded_csig, key_cattrs_hmac_256_bytes)

        ###################################
        # Decrypting Encrypted Attributes #
        ###################################
        # Any attributes namespaced with "ionic-protected-" should have been returned encrypted. ("ionic-integrity-hash" is a
        # special case that also is treated as an encrypted attribute.) To decrypt these attributes:
        # 1. Decode the cipher text using Base64. The cipher text contains the initialization vector, the data, and the auth tag.
        # 2. Decrypt the attributes using 256-bit AES-GCM.
        ## - The initialization vector is the first 16 bytes of the decoded bytes.
        ## - The auth tag is the last 16 bytes of the decoded bytes.
        ## - The key is the data key itself.
        ## - The additional authenticated data is the keytag of the key (in UTF-8 bytes).
        # 4. Decode the result - a JSON encoded array of string values.

        # cattrs is a string, so make it into an object.
        cattrs_dict = json.loads(key['cattrs'])

        # Iterate through the key's attributes searching for "ionic-protected-" prefixed attributes fields.
        for attr_name, attr_value in cattrs_dict.items():
            decrypted_keys[key_id]['attributes'] = cattrs_dict
            if attr_name.startswith('ionic-protected-'):
                # The attr_value is an array containing a base64 ciphertext string which is an encrypted stringified JSON array of values
                # 1. Decode the cipher text using Base64. The cipher text contains the initialization vector, the data, and the auth tag.
                b64encoded_ionic_protected_attrs = attr_value[0]
                encrypted_ionic_protected_attrs = base64.b64decode(
                    b64encoded_ionic_protected_attrs)  # we want to work with bytes

                # 2. Decrypt the attributes using 256-bit AES-GCM.
                ## The initialization vector is the first 16 bytes of the decoded bytes.
                attr_iv = encrypted_ionic_protected_attrs[:16]
                ## The data is in between the iv and the auth tag.
                attr_data = encrypted_ionic_protected_attrs[16:-16]
                ## The auth tag is the last 16 bytes of the decoded bytes.
                attr_auth_tag = encrypted_ionic_protected_attrs[-16:]
                ## The key is the data key itself.
                cipher = Cipher(algorithms.AES(decrypted_key_bytes),
                                modes.GCM(attr_iv,
                                          attr_auth_tag),
                                backend=default_backend()
                                ).decryptor()
                ## The additional authenticated data is the keytag of the key (in UTF-8 bytes).
                cipher.authenticate_additional_data(key_id.encode(encoding='utf-8'))
                decrypted_ionic_protected_attrs = cipher.update(attr_data) + cipher.finalize()

                # 3. Decode the result - a JSON encoded array of string values1.
                ionic_protected_attributes_array = json.loads(decrypted_ionic_protected_attrs.decode(encoding='utf-8'))
                decrypted_keys[key_id]['attributes'][attr_name] = ionic_protected_attributes_array

    return decrypted_keys, query_results
