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
# Author = rmspeers, QA = jmassey                         #
###########################################################

import json
import os

from .profile import DeviceProfile

####################################################
### Requires a Device Secure Enrollment Profile  ###
####################################################
# This file follows the ISAgentDeviceProfilePersistor format.
####################################################


class ProfilePersistorPlaintext():
    def __init__(self, filename=None):
        self.filename = filename
        self.seps = {}
        self.active_sep_id = None
        if filename is not None:
            self.load_from_json()

    def set_file_path(self, filename):
        self.filename = filename

    def set_active_profile(self, device_id):
        if device_id not in self.seps:
            raise Exception("Given device profile ID is set to a value which isn't recognized.")
        self.active_sep_id = device_id

    def get_active_profile(self):
        self.validate()
        return self.seps[self.active_sep_id]

    def get_seps(self):
        for sep in self.seps.values():
            yield sep

    def add_sep(self, device_profile_object, set_as_active=False):
        if device_profile_object.deviceId in self.seps:
            raise Exception("SEP already exists within the Profile Persistor's list.")
        self.seps[device_profile_object.deviceId] = device_profile_object
        if set_as_active:
            self.set_active_profile(device_profile_object.deviceId)

    def load_from_json(self):
        if not os.path.isfile(self.filename):
            raise IOError("The file path for the persistor must be set to a valid file before loading.")
        with open(self.filename, 'r') as fh:
            file_json = json.load(fh)
            profiles_list = []
            for profile_json in file_json['profiles']:
                profile = DeviceProfile()
                profile.load_from_object(profile_json)
                profile.validate()
                profiles_list.append(profile)
            if file_json['activeDeviceId'] not in map(lambda p: p.deviceId, profiles_list):
                raise Exception("Active device profile ID is set to a value which isn't in the list.")
            self.active_sep_id = file_json['activeDeviceId']
            for profile in profiles_list:
                self.add_sep(profile, set_as_active=False)

    def validate(self):
        for profile in self.seps.values():
            profile.validate()
        if self.active_sep_id not in self.seps:
            print(self.active_sep_id)
            raise Exception("Active device profile ID is set to a value which isn't recognized.")
        #TODO: Handle if there somehow was a duplicate of the same deviceId in the list.

    def save_to_json(self):
        self.validate()
        if self.filename is None:
            raise Exception("Must set a file path for the persistor to use before saving.")
        profiles_list = list(map(lambda p: p.export_as_object(), self.seps.values()))
        with open(self.filename, 'w') as fh:
            json.dump({'activeDeviceId': self.active_sep_id, 'profiles': profiles_list}, fh)

    def __repr__(self):
        return "ProfilePersistorPlaintext(active={0}, count={1})".format(self.active_sep_id, len(self.seps))
