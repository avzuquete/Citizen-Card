# Application that validates a citizen's certificates caried by their CC

This Java application validates the certificates contained in a CC.  Currently we only use the current time and CRL's (including Delta CRL's). In the future we plan to add OCSP validation.  

The application uses the IAIK PKCS #11 wrapper for extracting certificates out of the CC. You can also use the PTELIB for this (there is a Java wrapper for this one distributed with the CC software).

To run the application do the following:

1. Compile it using your preferred environment. Don't forget to use the IAIK JAR package in the java/lib directory of the IAIK wrapper zip file.

    To compile you can run the make command.

    This command also creates a keystore (CCkeystore) that will contain all know certificates belonging to the CC certification chains. The list of certificates may need to be updated (check the makefile).

2. Run the application in a directory containing the native wrapping library (get the right one in the native/platforms directory of the IAIK wrapper ZIP file).

3. Do not forget to provide the option -Djava.library.path=`pwd` to instruct the java VM to load the wrapping library from the current directory (which must be given with the full path).
    
```
java -cp ".:bin/iaikPkcs11Wrapper.jar" -Djava.library.path=`pwd` ccCertValidate
```

    Alternatively, you can skip the previous step and provide the path to the library where the wrapper library exists.

```
java -cp ".:bin/iaikPkcs11Wrapper.jar" -Djava.library.path=`pwd`/bin/unix/linux-x86_64/release ccCertValidate
```

    
4. Previously copy to the execution directory the directory of certificates distributed with the CC code (**eidstore/certs**). Keep this path from the execution directory (or edit the code for finding this certificates elsewhere).
