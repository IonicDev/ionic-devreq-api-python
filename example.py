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

    # Best practice is to include key attributes to describe the type of data you will be using this key to protect:
    ## These can either be `ionic-protected-*` prefixed so Ionic.com can't see them, and only other requestors who
    ##  access the key can; or they can be unencrypted so that Ionic.com can use their values in policy decisions.
    dictKeyAttrs = {
        'classification': 'Public',
        'ionic-protected-test': ['encrypted_value_1']
    }
    created_keys = create_keys(ionic_sep, dictKeyAttrs)
    print('Created keys: {}'.format(created_keys))

    # Now we show fetching one of these keys back:
    # NOTE: We may or may not be able to get it depending on the current data policy.
    print('Requesting the following keys by ID: {}'.format(', '.join(created_keys.keys())))

    # The value is a JSON object with a field "protection-keys" containing
    # an array of keytag strings. An example of the protection_keys array:
    # protection_keys = ["ABcdGadsg23", "ABcdGP34erq"]
    # See `example_external_ids.py` for another way to retrieve keys.
    fetched_keys = fetch_keys(ionic_sep, list(created_keys.keys()))
    print('Retrieved keys: {}'.format(fetched_keys))
