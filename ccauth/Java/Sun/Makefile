Auth_pkcs11.class: Auth_pkcs11.java
	JAVA_VERSION=`javac -version 2>&1 | cut -d " " -f 2 | cut -d "." -f 1`; \
	if [ $$JAVA_VERSION -lt 9 ]; then \
	    javac $^; \
	else \
	javac -Xdiags:verbose \
	    --add-modules jdk.crypto.cryptoki \
	    --add-exports java.base/sun.security.x509=ALL-UNNAMED \
	    --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED \
	    $^; \
	fi

Test.class: Test.java
	JAVA_VERSION=`javac -version 2>&1 | cut -d " " -f 2 | cut -d "." -f 1`; \
	if [ $$JAVA_VERSION -lt 9 ]; then \
	    javac $^; \
	else \
	javac -Xdiags:verbose \
	    $^; \
	fi
