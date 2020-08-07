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

import binascii
import json


class DeviceProfile():
    def __init__(self):
        self.deviceId = None
        self.server = None
        self.aesCdIdcKey = None
        self.aesCdEiKey = None
        self.name = None

    def load_from_object(self, json_object):
        if "deviceId" not in json_object or "server" not in json_object or \
           "aesCdIdcKey" not in json_object or "aesCdEiKey" not in json_object:
            raise Exception("JSON device profile object is missing one or more required fields.")

        self.deviceId = json_object["deviceId"]
        self.server = json_object["server"]
        self.name = json_object.get("name")
        self.set_keys_from_hex_strings(json_object["aesCdIdcKey"], json_object["aesCdEiKey"])

        #TODO: created time

    def set_keys_from_hex_strings(self, idc_key_in_hex_string, ka_key_in_hex_string):
        """
        Given a hex string representing each of the two AES-256 keys, convert this to the raw key for internal usage.
        :param idc_key_in_hex_string:
        :param ka_key_in_hex_string:
        :return:
        """
        self.aesCdIdcKey = binascii.unhexlify(idc_key_in_hex_string)
        self.aesCdEiKey = binascii.unhexlify(ka_key_in_hex_string)

    def validate(self):
        if self.deviceId is None or self.server is None or self.aesCdIdcKey is None or self.aesCdEiKey is None:
            raise Exception("Device profile object is missing one or more required fields.")

    def export_as_object(self):
        self.validate()
        json_object = {
            "deviceId": self.deviceId,
            "server": self.server,
            "aesCdIdcKey": binascii.hexlify(self.aesCdIdcKey).decode('utf-8'),
            "aesCdEiKey": binascii.hexlify(self.aesCdEiKey).decode('utf-8')
        }
        if self.name is not None:
            json_object["name"] = self.name
        #TODO: created time
        return json_object

    def __repr__(self):
        return json.dumps(self.export_as_object())

    def get_hfp_hash(self):
        #TODO: Implement
        return "aa0e43bfd6e7d5a9ea88e72d38d12df50bfb36e66710a5bb8417d8fb48230fc9"

    def get_hfp(self):
        #TODO: Implement
        return {'fptype':'example'}
