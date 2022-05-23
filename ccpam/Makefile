CC=g++
CFLAGS = -I /usr/local/include -g
PAM_INCLUDE_FILES = $(foreach f, pam_modules.h pam_client.h _pam_macros.h, /usr/include/security/$(f))

all: addCCuser pam_PTEIDCC.so

addCCuser: addCCuser.o CCkpubFile.o CCerrors.o
	$(CC) -o $@ $^ -L /usr/local/lib -lpteidlib -lcrypto
	strip $@

addCCuser.o: addCCuser.c CCkpubFile.h CCerrors.h
	$(CC) -o $@ -c $*.c $(CFLAGS)

pam_PTEIDCC.so: pam_PTEIDCC.o CCkpubFile.o
	ld -o $@ -shared $^ -L /usr/local/lib -lpam -lpteidpkcs11 -lcrypto

CCkpubFile.o: CCkpubFile.c CCkpubFile.h
	$(CC) -o $@ -c -fPIC $*.c $(CFLAGS)

pam_PTEIDCC.o: pam_PTEIDCC.c CCkpubFile.h
	@for f in $(PAM_INCLUDE_FILES); do \
		if test ! -f $$f; then \
			echo "install libpam0g-dev with apt-get or with a similar tool"; \
			exit 1; \
		fi; \
	done; \
	echo $(CC) -o $@ -c -fPIC -fno-stack-protector $*.c $(CFLAGS); \
	$(CC) -o $@ -c -fPIC -fno-stack-protector $*.c $(CFLAGS)

install:
	strip pam_PTEIDCC.so
	@libpam=`find /usr/lib -name libpam.so`; \
	targets=`strings $$libpam | grep ^/lib`; \
	for t in $$targets; do \
	    [ -d $$t ] && ( \
		echo "Copy pam_PTEIDCC.so to $$t"; \
		cp pam_PTEIDCC.so $$t; \
		cp addCCuser /usr/local/bin; \
		[ -d /etc/CC ] || ( \
		    echo "Created file /etc/CC"; \
		    mkdir /etc/CC; \
		); \
	    ); \
	done
	
clean:
	rm *.o addCCuser pam_PTEIDCC.so
