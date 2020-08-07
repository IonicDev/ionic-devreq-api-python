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

import sys
import os

from registration import create_device
from registration import get_ionic_token
from persistors import ProfilePersistorPlaintext

####################################################
### Creates a Device Secure Enrollment Profile   ###
####################################################
# It will output SEP to a file named `profiles.pt` #
# which contains a plaintext SEP for demo purposes #
# only. Use a different persistor type in real use.#
####################################################

# TODO:
# If you are using Ionic's IdP, you can enter your username
# and password below. If not, you must obtain a UIDAUTH
# and STOKEN before registering. These must be unique to each
# registration to prevent replay attacks. 

user = ""
password = r""

stoken = ""
uidauth = ""

# These URLs are valid if you obtained your tenant using Start for Free, https://ionic.com/start-for-free/.
# Modify the keyspace to the keyspace of your tenant.
api_url = "https://api.ionic.com"
enrollment_server_url = "https://enrollment.ionic.com"
keyspace = "ABcd"


if __name__ == "__main__":
    # Validate the user provided input:
    if api_url == "" or enrollment_server_url == "" or keyspace == "":
        print("ERROR: api_url, enrollment_server_url, and keyspace must all be defined.")
        sys.exit(1)
    if user != "" and password != "":
        enrollment_url = "{}/keyspace/{}/register".format(enrollment_server_url, keyspace)
        stoken, uidauth = get_ionic_token(enrollment_url, user, password)
    if stoken == "" or uidauth == "":
        print("ERROR: Username and Password or STOKEN and UIDAUTH must be defined")
        sys.exit(2)

    # Generate the request body, make the request, and decrypt the responses from the key server and Ionic.com
    sep = create_device(api_url, keyspace, enrollment_server_url, stoken, uidauth)
    # Display the profile received
    print(sep)

    # Save the profile to a file
    # NOTE: This will overwrite any existing content at that path.
    persistor = ProfilePersistorPlaintext()
    persistor.add_sep(sep, set_as_active=True)
    persistor_path = os.path.expanduser("~/.ionicsecurity/profiles.pt")
    persistor.set_file_path(persister_path)
    print(persistor)
    persistor.save_to_json()
