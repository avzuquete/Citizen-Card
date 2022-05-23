# Authentication with the Portuguese Citizen card and the Sun PKCS #11 provider

In this directory you can find a demo applications in Java that performs an authentication with a CC's private authentication key. The application also verifies the authentication signature using the corresponding public key certificate, extracted from the CC.

This demo file uses the Sun PKCS #11 provider. Note that this
provider does not work in 64 bit machines!

To run this application do the following:

1. Compile it using your preferred environment.

2. Copy to this directory the CC's PKCS #11 library (for each operating system). Currently the program is prepared to use Windows and Linux libraries.
