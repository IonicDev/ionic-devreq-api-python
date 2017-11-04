############################################################
# This is a code sample for the Ionic Security Inc. API,   #
# specifically obtaining an Ionic Assertion from the       #
# enrollment server, assuming the enrollment server uses   #
# the Ionic IdP configuration (typically for demo/dev use).#
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
# Author = jmassey, QA = rmspeers                          #
############################################################

import requests


def get_authn(enrollment_url):
    print(enrollment_url)
    enrollment_get_authn = requests.get(enrollment_url)
    print(enrollment_get_authn.headers)
    try:
        idp_url = enrollment_get_authn.headers["X-Saml-Redirect"]
    except:
        raise Exception("Unable to retrieve the URL of the IdP.")

    try:
        saml_body = enrollment_get_authn.headers["X-Saml-Request"]
    except:
        raise Exception("Unable to retrieve saml body")

    try:
        relay_state = enrollment_get_authn.headers["X-Saml-Relay-state"]
    except:
        raise Exception("Unable to retrieve relay state.")

    return idp_url, saml_body, relay_state


def get_assertion(user, password, idp_url, saml_body):
    data = {"user": user, "password": password, "SAMLRequest": saml_body}
    login_response = requests.post(idp_url, data)
    saml_assertion = login_response.headers.get("X-Saml-Response", None)

    if saml_assertion is None:
        raise Exception("Unable to retrieve SAML assertion.")

    return saml_assertion


def post_assertion(saml_assertion, relay_state):
    enroll_data = {"SAMLResponse": saml_assertion, "RelayState": relay_state}
    enrollment_post_assertion = requests.post(relay_state, enroll_data)
    try:
        stoken = enrollment_post_assertion.headers["X-Ionic-Reg-Stoken"]
    except:
        raise Exception("Unable to retrieve Stoken")

    try:
        uidauth = enrollment_post_assertion.headers["X-Ionic-Reg-Uidauth"]
    except:
        raise Exception("Unable to retrieve uidauth")

    return stoken, uidauth


def get_ionic_token(enrollment_url, user, password):
    idp_url, saml_body, relay_state = get_authn(enrollment_url)
    saml_assertion = get_assertion(user, password, idp_url, saml_body)
    stoken, uidauth = post_assertion(saml_assertion, relay_state)
    return stoken, uidauth
