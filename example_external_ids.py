###########################################################
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
# Author = rmspeers, QA =                                 #
###########################################################

from uuid import uuid4

from keys import create_keys, fetch_keys
from persistors import ProfilePersistorPlaintext

####################################################
### Requires a Device Secure Enrollment Profile  ###
####################################################
# Assume a SEP saved to a file named `profiles.pt` #
# which contains a plaintext SEP for demo purposes #
# only. Use a different persistor type in real use.#
####################################################

if __name__ == "__main__":
    persistor = ProfilePersistorPlaintext('profiles.pt')
    ionic_sep = persistor.get_active_profile()

    # We generate, via whatever method, an external ID which allows us an alternate way to query for the key.
    external_id = uuid4().hex
    print('We will be referencing: {}'.format(external_id))

    # Best practice is to include key attributes to describe the type of data you will be using it to protect:
    # See `example.py` for other options, including using encrypted attributes.
    dictKeyAttrs = {'classification': 'Public'}
    dictKeyAttrs["ionic-external-id"] = [external_id]

    created_keys = create_keys(ionic_sep, dictKeyAttrs)
    print('Created keys: {}'.format(created_keys))

    # Now we show fetching these keys back, using the external ID _instead of the key ID_:
    # NOTE: We may or may not be able to get it depending on the current data policy.
    print('We could request these keys by ID: {}'.format(', '.join(created_keys.keys())))

    # The value is a JSON object with a field "protection-keys" containing
    # an array of keytag strings. An example of the protection_keys array:
    # protection_keys = ["ABcdGadsg23", "ABcdGP34erq"]
    print('However instead we will query for the key by the external ID we gave it: {}'.format(external_id))
    protection_keys = []            # Can define to an empty array if only want to query by external_ids.
    external_ids = [external_id]    # Can define to None if only want to query by key IDs (as is typical).
    decrypted_keys, query_results = fetch_keys(ionic_sep, protection_keys, external_ids=external_ids)
    print('Fetch keys: {}'.format(decrypted_keys))
    if query_results is not None:
        print('Query results: {}'.format(query_results))
