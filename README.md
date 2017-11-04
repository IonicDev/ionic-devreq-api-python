# ionic-devreq-api-python: Example Code for Interacting with Ionic's Device Request API

## Explanation

This example code shows how to use the advanced Device Request APIs available from the Ionic Platform.
It is meant to serve as sample code for developers learning about those APIs to use as reference.

Most developers will instead prefer to use Ionic's supported SDKs, which include a Python SDK which has the same
 functionality shown in these examples, as well as significant additional features.

## Setting up Environment

You may want to use Python's virtualenv toolkit to manage your environment.

Once loaded, install the pre-requisites:
```bash
pip install -r requirements.txt
```

## Running Examples

### Create and Fetch Keys:

The `example.py` tool shows how to create keys, and then request them again.
These two operations are usually done independently.

Using this example requires a Secure Enrollment Profile (SEP), which it expects via the plaintext profile persistor in a file `profiles.pt`.
Read [Enrollment Overview](https://dev.ionic.com/registration.html) to learn more.
See the Enrollment Example for obtaining one if you don't have one via another mechanism.

### Enrolling:

The `example_enroll.py` tool shows enrolling a device and obtaining a SEP, and then storing it using the plaintext profile persistor.

Using this example requires first editing the code to define the correct values for the variables.
After setting those values, it can be run and will produce `profiles.pt` which is the SEP stored in plaintext.

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
