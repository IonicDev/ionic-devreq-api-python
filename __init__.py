############################################################
# This is a code sample for the Ionic Security Inc. API,   #
# and this packages it so it is usable by other examples.  #
# The intention is to show how to interact with the API    #
# using builtin and 3rd-party libraries instead of the     #
# Ionic SDK.                                               #
#                                                          #
# (c) 2017 Ionic Security Inc.                             #
# Confidential and Proprietary                             #
# By using this code, I agree to the Terms & Conditions    #
#  (https://www.ionic.com/terms-of-use/) and the Privacy   #
#  Policy (https://www.ionic.com/privacy-notice/)          #
############################################################

from registration.registration import create_device
from keys.keys import create_keys, fetch_keys
import persistors.persistors
