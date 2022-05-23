# Authentication with the Portuguese Citizen card and the IAIK wrapper

In this directory you can find two demo applications in Java that perform an authentication with a CC's private authentication key. The applications also verify the authentication signature using the corresponding public key certificate, extracted from the CC.

Both Java files use the IAIK PKCS#11 wrapper, but differently.

1. Auth\_pkcs11\_API uses the standard PKCS#11 API over a PKCS#11 module object. It performs 3 tests:
    - PKCS#11 internal digest and Java signature validation digest (CMK\_\*\_RSA\_PKCS, \*withRSA)
    - External digest (CKM\_RSA\_PKCS, NONEwithRSA).
    - External ASN.1 wrapped digest and Java signature validation digest (CKM\_RSA\_PKCS, \*withRSA)
  
2. Auth\_pkcs11\_objects uses different classes to interact with a PKCS #11 token, such as module, token, session, key, etc. for testing several hash functions to perform signatures and validations.

To run these applications do the following:

1. Compile them using your preferred environment. Don't forget to use the IAIK JAR package in the java/lib directory of the IAIK wrapper ZIP file. The make command, with the help of the Makefile, does this job for you.

2. Run them in a directory containing the native wrapping library (get the right one in the native/platforms directory of the IAIK wrapper zip file).

3. Do not forget to provide the option -Djava.library.path=`pwd` to instruct the java VM to load the wrapping library from the current directory (which must be given with the full path):
    
```
java -cp ".:bin/iaikPkcs11Wrapper.jar:bin/bcprov-jdk15on-159.jar" -Djava.library.path=`pwd` Auth_pkcs11_API /usr/local/lib/libpteidpkcs11.so
```

Alternatively, you can skip the previous step (2) and provide the path to the library where the wrapper library exists:

```
java -cp ".:bin/iaikPkcs11Wrapper.jar:bin/bcprov-jdk15on-159.jar" -Djava.library.path=`pwd`/bin/unix/linux-x86_64/release Auth_pkcs11_API /usr/local/lib/libpteidpkcs11.so
```
