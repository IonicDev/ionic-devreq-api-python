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
import binascii
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


def encrypt_key_attribute(ionic_sep, encrypted_attributes_name, attribute_values_to_encrypt):
    # To construct encrypted attributes:
    ## 1. Encode the original values as a JSON array in UTF-8.
    ## 2. Encrypt the encoded values using `SEP.CD:KS` key under 256-bit AES in GCM with the UTF-8 encoded attribute name used as
    ##    additional authenticated data. The initialization vector should be prepended to the cipher text and the auth tag should
    ##    be appended to the cipher text.
    ## 3. Encode the result using Base64.
    ## 4. Add the resulting string as the only value in the list under the attribute name.

    # 1. Encode the original values as a JSON array in UTF-8.
    json_array_of_attribute_values_to_encrypt = json.dumps(attribute_values_to_encrypt).encode(encoding='utf-8')

    # 2. Encrypt the encoded values using `SEP.CD:KS` key under 256-bit AES in GCM with the UTF-8 encoded attribute name used as
    #    additional authenticated data. The initialization vector should be prepended to the cipher text and the auth tag should
    #    be appended to the cipher text.
    # Create a 16-byte initialization vector of random bytes.
    attributes_to_encrypt_initialization_vector = os.urandom(16)

    # Create an AES-GCM cipher using the `SEP.CD:KS` as the key and the 16-byte initialization vector
    cipher = Cipher(algorithms.AES(ionic_sep.aesCdEiKey),
                    modes.GCM(attributes_to_encrypt_initialization_vector),
                    backend=default_backend()
    ).encryptor()

    # Set the authenticated data (AAD) to be the attributes name UTF-8 encoded
    cipher.authenticate_additional_data(encrypted_attributes_name.encode(encoding='utf-8'))

    # Encrypt the JSON array of attributes as UTF-8 bytes using 256-bit AES in GCM.
    attributes_to_encrypt_cipher_text = cipher.update(json_array_of_attribute_values_to_encrypt) + cipher.finalize()

    # Prepend the 16-byte initialization vector to the cipher text and append the auth tag to the cipher text.
    ## Prepend the resulting cipher text bytes with the initialization vector.
    ## Append the auth tag to the resulting cipher text.
    attributes_to_encrypt_iv_cipher_text_aad_bytes = b''.join([attributes_to_encrypt_initialization_vector,
                                                         attributes_to_encrypt_cipher_text,
                                                         cipher.tag])

    # 3. Encode the result using Base64
    return base64.b64encode(attributes_to_encrypt_iv_cipher_text_aad_bytes)


def create_key_transaction(ionic_sep, dictKeyAttrs, dictMetadata, send_full_hfp=False):
    ###########################################
    ### Constructing the Key Create Request ###
    ###########################################
    # NOTE: This type of request when encrypting attributes and performing attribute signing requires
    # a conversation id (`cid`) to be used in AES-GCM encryption operations. We must construct the `cid`
    # prior to performing any of these integrity ensuring cryptographic operations. Hence, the steps
    # for constructing a device request as listed generally previously are modified here.
    example_key_create_request_body = """
    {
      "cid": "CID|MfyG..A.ec095b70-c1d0-4ac0-9d0f-2cafa82b8a1f|1487622171374|1487622171374|5bFnTQ==",
      "envelope": {
        "meta": {
          "hfphash": "aa0e43bfd6e7d5a9ea88e72d38d12df50bfb36e66710a5bb8417d8fb48230fc9",
        },
        "data": {
          "protection-keys": [
            {
              "ref":"firstKeyType",
              "qty":1,
              "cattrs": "{\"attr1\":[\"attr1val1\",\"attr1val2\"],\"attr2\":[\"attr2val1\"]}",
              "csig": "oRPW3N3a4CKdwhV00XlJKLZ/4GTjWJ+V4MJh2Ry3Z5g="
            }
          ]
        }
      }
    }
    """

    # 1. Compose a Conversation ID string in a UTF-8 encoded byte array.
    ## Choose the appropriate SEP for this request.
    cid = utilities.make_cid(ionic_sep.deviceId)

    # 2. Construct the request data.
    # The value is a JSON object with a field "protection-keys" containing
    # an array of key creation objects.
    # NOTE: This represents a very basic key create object.
    ref1 = "refType1"
    key_create_data = {
        "protection-keys": [
            {
                "qty": 1,
                "ref": ref1
            }
        ]
    }

    # NOTE: The following shows how to add encrypted attributes to a key creation object. This must be performed before
    # the next step of Signing Attributes because this data will be contained within the object constructed in the next
    # section (Keys with Signed Attributes)
    ###################################
    ### BEGIN: Encrypted Attributes ###
    ###################################
    # The device may encrypt attributes such that Ionic.com cannot see them in transition to the keyserver.
    ## NOTE: Such attributes cannot affect the policies applied to those keys as the policy server also cannot decrypt those attributes.
    # The encrypted attributes should be namespaced with ionic-protected-.
    ## (ionic-integrity-hash is a special case that also is treated as an encrypted attribute.)

    dictKeyAttrs_keysToEncrypt = filter(lambda x: x.startswith('ionic-protected-'), dictKeyAttrs.keys())
    if 'ionic-integrity-hash' in dictKeyAttrs:
        dictKeyAttrs_keysToEncrypt.append('ionic-integrity-hash')

    # For each attribute where we want the values encrypted, perform the encryption and overwrite the plaintext value:
    for encrypted_attribute_name in dictKeyAttrs_keysToEncrypt:
        b64_encrypted_attributes = encrypt_key_attribute(ionic_sep, encrypted_attribute_name, dictKeyAttrs[encrypted_attribute_name])
        dictKeyAttrs[encrypted_attribute_name] = [b64_encrypted_attributes.decode(encoding='utf-8')]

    # We now have a field name and values to add to the attributes field (`cattrs`) constructed below
    # We will perform step 4 during the final creation of the cattrs object.
    #################################
    ### END: Encrypted Attributes ###
    #################################

    # NOTE: The follow shows how to create a key with signed attributes to ensure integrity of attribute data.
    ##########################################
    ### BEGIN: Keys with Signed Attributes ###
    ##########################################
    # Keys with Signed Attributes
    ## 1. Prepare the required attributes. Each attribute contains a name and a list of values.
    ## 2. Encode the attributes into a JSON object encoded in UTF-8 bytes.
    ## 3. Compute the SHA256 hash of those bytes.
    ## 4. Form the authenticated data as the UTF-8 representation of the ref field appended to the Conversation ID
    ##    separated by a colon (:), like CID|Mfyg...|..4b:refID1.
    ## 5. Encrypt the attribute hash bytes using 256-bit AES in GCM.
    ### - Construct a nonce 16-byte initialization vector.
    ### - Use the additional authenticated data constructed from the prior step.
    ### - The key to be used is the SEP.CD:KS key.
    ## 6. Prepend the 16-byte initialization vector to the cipher text and append the auth tag to the cipher text.
    ## 7. Base64-encode the combined initialization vector and cipher text bytes.

    # 1a. Attributes should be set by the caller of this function, such as:
    #dictKeyAttrs = {"keyType1AttributeField1": ["keyType1AttributeValue1"]}

    # 1b. We can add an external ID into this list. If desired, the caller of this function should set it such as:
    #dictKeyAttrs["ionic-external-id"] = ["exampleExternalID"]

    # The field name and value of the Encrypted Attributes were already placed here in the above code.

    # The data sent to Ionic will be the stringified `cattrs` object
    cattrs_as_string = json.dumps(dictKeyAttrs)

    # 2. Encode the attributes into a JSON object encoded in UTF-8 bytes.
    cattrs_as_bytes = cattrs_as_string.encode(encoding='utf-8')

    # 3. Compute the SHA256 hash of those bytes.
    sha256er = hashlib.sha256()
    sha256er.update(cattrs_as_bytes)
    cattr_sha256_bytes = sha256er.digest()

    # 4. Form the authenticated data as the UTF-8 representation of the ref field appended to the Conversation ID
    #    separated by a colon (:), like CID|Mfyg...|..4b:refID1.
    signed_attributes_aad = ':'.join([cid, ref1])

    # 5. Encrypt the attribute hash bytes using 256-bit AES in GCM.
    # - Construct a nonce 16-byte initialization vector.
    signed_attributes_initialization_vector = os.urandom(16)

    # Create an AES-GCM cipher using the SEP.CD:KS as the key and the 16-byte initialization vector
    # - The key to be used is the `SEP.CD:KS` key
    cipher = Cipher(algorithms.AES(ionic_sep.aesCdEiKey),
                    modes.GCM(signed_attributes_initialization_vector),
                    backend=default_backend()
                    ).encryptor()

    # - Use the additional authenticated data constructed from the prior step.
    ## Set the authenticated data (AAD) to be the signed attributes AAD (<CID>|<refType>)
    cipher.authenticate_additional_data(signed_attributes_aad.encode(encoding='utf-8'))

    signed_attributes_cipher_text = cipher.update(cattr_sha256_bytes) + cipher.finalize()

    # 6. Prepend the 16-byte initialization vector to the cipher text and append the auth tag to the cipher text.
    signed_attributes_iv_cipher_text_aad = b''.join([signed_attributes_initialization_vector,
                                                     signed_attributes_cipher_text,
                                                     cipher.tag])

    # 7. Base64-encode the combined initialization vector and cipher text bytes.
    b64encoded_signed_attributes_iv_cipher_text_aad_as_string = base64.b64encode(signed_attributes_iv_cipher_text_aad).decode(encoding='utf-8')

    # Add the attributes and signature to the key creation object
    # `cattrs` is the stringified object
    key_create_data['protection-keys'][0]['cattrs'] = cattrs_as_string
    key_create_data['protection-keys'][0]['csig'] = b64encoded_signed_attributes_iv_cipher_text_aad_as_string
    ########################################
    ### END: Keys with Signed Attributes ###
    ########################################

    # 3. Construct or obtain a cached copy of the needed meta data.
    ## - This will include the hfphash.
    ## - If an update is needed, this should include the full hfp.
    # NOTE: This represents the minimum contents, and it assumes that device's fingerprint is saved in IDC and has not changed locally.
    # Therefore we can send only the `hfphash`.
    # Here the `hfphash` is obtained from the `ionic_sep` dict:
    hfphash = ionic_sep.get_hfp_hash()

    # 4. Compose the `meta` and `data`. Serialize the JSON object containing `meta` and `data` as fields to a byte array
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
            "data" : key_create_data
        }
    else:
        envelope_contents = {
            "meta": {
                "hfphash": hfphash
            },
            "data" : key_create_data
        }

    # Serialize the `envelope` contents to a byte array containing the UTF-8 encoding of the contents
    serialized_envelope_contents = json.dumps(envelope_contents).encode(encoding='utf-8')

    # 5. Encrypt the array of JSON bytes using AES-256 GCM. AES-256 GCM encryption requires a key, an initialization vector,
    #    and auth data (also called AAD). Encryption returns both encrypted bytes and an auth tag.
    ## - Use the SEP.CD:IDC value as the key.
    ## - Create a 16-byte initialization vector of random bytes.
    ## - Set the authenticated data (AAD) to be the Conversation ID byte array.
    ## - Encrypt the JSON byte array.

    # Create a 16-byte initialization vector of random bytes.
    initialization_vector = os.urandom(16)

    # Create an AES-GCM cipher using the SEP.CD:IDC as the key and the 16-byte initialization vector
    cipher = Cipher(algorithms.AES(ionic_sep.aesCdIdcKey),
                    modes.GCM(initialization_vector),
                    backend=default_backend()
                    ).encryptor()

    # Set the authenticated data (AAD) to be the Conversation ID byte array.
    cipher.authenticate_additional_data(cid.encode(encoding='utf-8'))

    # Encrypt the JSON byte array.
    cipher_text = cipher.update(serialized_envelope_contents) + cipher.finalize()

    # 6. Combine the initialization vector, the encrypted JSON, and the auth tag.
    iv_cipher_text_aad = b''.join([initialization_vector,
                                   cipher_text,
                                   cipher.tag])

    # 7. Encode the results of the previous step as a single array of bytes using Base64.
    b64encoded_iv_cipher_text_aad_as_string = base64.b64encode(iv_cipher_text_aad).decode(encoding='utf-8')

    # 8. Compose a JSON representation containing the resulting Base64-encoded string as the value
    #    of the envelope field and the Conversation ID string as the value of the cid field.
    # This representation should use UTF-8 encoding.
    key_create_request_body = {
        "cid": cid,
        "envelope": b64encoded_iv_cipher_text_aad_as_string
    }

    # Send the request to Ionic as an HTTP POST with JSON data to https://dev-api.ionic.com/v2.3/keys/create
    print('Creating keys: {}'.format(key_create_data))
    key_create_response = requests.post('%s/v2.3/keys/create' % ionic_sep.server,
                                        data=json.dumps(key_create_request_body),
                                        headers={'Content-Type': 'application/json'})


    ########################################
    ### Handling the Key Create Response ###
    ########################################
    # Assume the response from Ionic is a successful 200, and we have created keys with the provided attributes.
    status_code = key_create_response.status_code
    assert (status_code == 200) or (status_code == 201), "\nKey Create response status code: %d\n" % status_code

    return key_create_response, cid, b64encoded_signed_attributes_iv_cipher_text_aad_as_string


def create_keys(ionic_sep, dictKeyAttrs = {}, dictMetadata = {}):
    # See https://dev.ionic.com/api/device/create-key for more information on key create.

    key_create_response, cid, b64encoded_signed_attributes_iv_cipher_text_aad_as_string = create_key_transaction(ionic_sep, dictKeyAttrs, dictMetadata)
    decrypted_envelope, response_cid = utilities.decrypt_envelope(ionic_sep, key_create_response, cid)

    # NOTE: It is possible that an error occurred, perhaps the time recorded by the client and that held by the server differ
    # more than +/-5 minutes or the device needs to send its entire fingerprint (`hfp`).
    # Please see the errors and error handling for more information.
    if decrypted_envelope.get('error'):
        print("\nA partial error has occurred. The following is the response from the server:")
        print(decrypted_envelope["error"])
        if decrypted_envelope["error"]["code"] == 4001:
            print("\nIn this scenario, the hfphash is not recognized by the server. A new request will be generated with "
                  "the full HFP included.")
            key_create_response, cid, b64encoded_signed_attributes_iv_cipher_text_aad_as_string = create_key_transaction(ionic_sep, dictKeyAttrs, dictMetadata, send_full_hfp=True)
            decrypted_envelope, response_cid = utilities.decrypt_envelope(ionic_sep, key_create_response, cid)

    example_key_create_response_keys = """
    {
      "cid": "CID|MfyG..A.ec095b70-c1d0-4ac0-9d0f-2cafa82b8a1f|1487622171374|1487622171374|5bFnTQ==",
      "envelope": {
        "data": {
          "protection-keys": [
            {
              "ref":"firstKeyType",
              "id": "MfygGadsg23",
              "key":"ad01f035b2b45967f71099ca29893381675904941bd91a72a0044e9e3087eaf2bafa07b6e106361a3acb1e2eb6e191e5fad50690f0b97871414b256e496aed38"
            },
            {
              "ref":"secondKeyType",
              "id": "MfygGP34erq",
              "key":"f980333fb2b6da08f7e02b9d8e5f2b3f2c119777962c92f02b8a19276766fe675b26773ca69c417e5f957a7e58922d1e7da28f9349f35eac8afb5d35fd83bc69"
            },
            {
              "ref":"secondKeyType",
              "id": "MfygGP2Dg19",
              "key":"c2221c814c5a1acacde0671c3b5e53786ec67851da7ca2455ab7640b7dd02b0d50a1706bb6bb80fe8baf05ec796f45532cb3a808c39a9d7669bb2c169db576f8"
            },
            {
              "ref":"secondKeyType",
              "id": "Mfygm6sdzcx",
              "key":"e7ee8f671d73aff9c02ff002e2732ddea5f3716bab98ccbdd7514bb4b32d1ecd67209ad1127ce22b10a0d190448ea285e71dcd068bee8d5b647a9ffbe9342a27"
            }
          ]
        }
      }
    }
    """

    # To decrypt each returned data key:
    ## 1. Decode the contents of the `key` field using hex. The cipher text contains the initialization vector,
    #     the data, and the auth tag.
    ## 2. Form the additional authenticated data for the key.
    ### - This is the UTF-8 representation of the Conversation ID, `ref` field, and
    ###   `id` field separated by colons (`:`), like `CID|Mfyg...|..4b:firstKeyType:MfygGadsg23`.
    ### - If the attributes for that key were signed, the Base64-encoded signature
    ###   field from the request is also included in the auth data, like
    ###   `CID|Mfyg...|..4b:firstKeyType:MfygGadsg23:oRPW3N3a4...MJh2Ry3Z5g=`.
    ## 3. Decrypt the decoded key bytes using 256-bit AES GCM.
    ### - The initialization vector is the first 16 bytes of the decoded bytes.
    ### - The auth tag is the last 16 bytes of the decoded bytes.
    ### - The key is the `SEP.CD:KS` key.
    ### - The additional authenticated data are the bytes formed in the previous step.
    ## The result is a 256-bit AES key in raw bytes.

    decrypted_keys = {}  # simple storage for the data we're decrypting from the response
    for key in decrypted_envelope['data']['protection-keys']:
        key_id = key['id']
        key_ref = key['ref']
        aad = ':'.join([response_cid, key_ref, key_id, b64encoded_signed_attributes_iv_cipher_text_aad_as_string])
        hex_encoded_encrypted_key = key['key']
        encrypted_key_bytes = binascii.unhexlify(hex_encoded_encrypted_key)
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
        # The ref can be used for grouping types of keys with similar attributes
        decrypted_keys[key_id] = key
        decrypted_keys[key_id]['ref'] = key_ref
        decrypted_keys[key_id]['key'] = decrypted_key_bytes

    return decrypted_keys
