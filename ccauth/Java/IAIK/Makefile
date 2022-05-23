ifeq "$(OS)" "Windows_NT"
PATH_SEP = \\
PATH_ADD = ;
else
PATH_SEP = /
PATH_ADD = :
endif

IAIK_PATH = bin$(PATH_SEP)iaikPkcs11Wrapper.jar
BC_PATH = bin$(PATH_SEP)bcprov-jdk15on-159.jar

PTEID_LINUX_PATH = /usr/local/lib
PTEID_WINDOWS_PATH = /cygdrive/c/Windows/System32

all: API API_MD5 API_SHA API_SHA1 API_SHA256 API_SHA384 API_SHA512 API_RIPEMD160 API_ASN1 objects

API: Auth_pkcs11_API.class

API_MD5: Auth_pkcs11_API_MD5.class

API_SHA: Auth_pkcs11_API_SHA.class

API_SHA1: Auth_pkcs11_API_SHA1.class

API_SHA256: Auth_pkcs11_API_SHA256.class

API_SHA384: Auth_pkcs11_API_SHA384.class

API_SHA512: Auth_pkcs11_API_SHA512.class

API_RIPEMD160: Auth_pkcs11_API_RIPEMD160.class

API_ASN1: Auth_pkcs11_API_ASN1.class

objects: Auth_pkcs11_objects.class

%.class: %.java
	JAVA_VERSION=`javac --version | cut -d " " -f 2 | cut -d "." -f 1`; \
	if [ $$JAVA_VERSION -lt 9 ]; then \
            javac -cp "$(IAIK_PATH)$(PATH_ADD)$(BC_PATH)" $^ -Xlint; \
	else \
	javac -cp "$(IAIK_PATH)$(PATH_ADD)$(BC_PATH)" -Xdiags:verbose \
	    --add-modules jdk.crypto.cryptoki \
	    $^; \
        fi

run_%:
	if [ `uname` = "Linux" ]; then \
            make run_$*_linux64; \
        else \
            make run_$*_win64; \
        fi

run_%_linux64:
	java -cp ".:bin/iaikPkcs11Wrapper.jar:bin/bcprov-jdk15on-159.jar" -Djava.library.path=`pwd`/bin/unix/linux-x86_64/release Auth_pkcs11_$* $(PTEID_LINUX_PATH)/libpteidpkcs11.so

run_API_windows64:
	java -cp ".:bin/iaikPkcs11Wrapper.jar:bin/bcprov-jdk15on-159.jar" -Djava.library.path=`pwd`/bin/windows/win_x64/release Auth_pkcs11_API $(PTEID_WINDOWS_PATH)/libpteidpkcs11.dll

clean:
	rm *.class
