# ionic-devreq-api-python: Example Code for Interacting with Ionic's Device Request API

## Explanation

This example code shows how to use the advanced [Device Request APIs](https://dev.ionic.com/api/device) available from the Machina Platform.
It is meant to serve as sample code for developers learning about those APIs to use as reference.

Most developers will instead prefer to use [Ionic's supported SDK](https://dev.ionic.com/sdk/features), which include a Python SDK which has the same
 functionality shown in these examples, as well as significant additional features. There are SDK examples for [Create Key](https://dev.ionic.com/sdk/tasks/create-key?language=python) and [Get Key](https://dev.ionic.com/sdk/tasks/get-key?language=python).

## Setting up Environment

You will need to obtain a tenant. A free tenant can be obtained [here](https://ionic.com/start-for-free/). By following the prompted path, your
device will be enrolled.

## Setting up Development Environment

You may want to use Python's virtualenv toolkit to manage your environment.

Once loaded, install the pre-requisites:

```
pip install -r requirements.txt
```

## Running Examples

### Create and Fetch Keys:

The `example.py` sample shows how to create keys, and then request them again.
These two operations are usually done independently.

Using this example requires a Secure Enrollment Profile (SEP), which it expects via the plaintext profile persistor in a file `$HOME/.ionicsecurity/profiles.pt`.
Read [Enrollment Overview](https://dev.ionic.com/registration.html) to learn more.
See **Enrolling** below if you didn't enroll via another mechanism.

This example shows how to use the [Create Key API](https://dev.ionic.com/api/device/create-key) and the [Get Key API](https://dev.ionic.com/api/device/get-key).

### Enrolling

The `example_enroll.py` tool shows enrolling a device and obtaining a SEP, and then storing it using the plaintext profile persistor.

Using this example requires first editing the code to define the correct values for the variables.
After setting those values, it can be run and will produce `$HOME/.ionicsecurity/profiles.pt` which is the SEP stored in plaintext.

There are two options for setting the values:

#### Provide Username/Password for Ionic IdP-linked Enrollment Servers

If, and only if, your enrollment server is linked to Ionic's IdP (which is only for development/demo environments), then
 you can enter your Ionic username and password in the file (for demonstration purposes only) and it will obtain the
 stoken/uidauth values for you.

#### Provide stoken/uidauth Obtained from Any Enrollment Method

These values are typically obtained from doing the workflows described in [Enrollment Overview](https://dev.ionic.com/registration.html),
 such as SAML, Oauth, email token, or generated SAML assertions.
You will need to perform the communication with the enrollment server, following the process for your selected
 enrollment type, to obtain these values before entering them and then running this script. 
See `registration/get_ionic_token.py` for an example of doing this for a SAML enrollment against the demonstration Ionic IdP.
