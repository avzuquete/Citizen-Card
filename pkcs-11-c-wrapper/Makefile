PKCS11_API_URL = https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/include/pkcs11-v3.0

PKCS11_API_FILES = \
        pkcs11.h \
        pkcs11f.h \
        pkcs11t.h

PKCS11_LIB = /usr/local/lib/libpteidpkcs11.so
CLEAN_API_H = pkcs11f-clean.h

pkcs11.so:  $(PKCS11_API_FILES) api.o
	gcc -o $@ -Bdynamic -shared api.o -ldl

$(PKCS11_API_FILES):
	wget $(PKCS11_API_URL)/$@

api.o: api.c bootstrap.c
	gcc -o $@ -c api.c -fpic

api.c: $(PKCS11_LIB) $(CLEAN_API_H)
	nm -AD $(PKCS11_LIB) | grep " T " | grep C_ | awk '{print $$3}' > api
	( echo '#include "bootstrap.c"'; \
	echo "\nvoid\nresolve()\n{"; \
	for name in `cat api`; do \
            echo "\t_funcs.$$name = $$name;"; \
	done; \
	echo "}\n\n"; \
	for name in `cat api`; do \
            line=`grep "CK_RV $$name (" $(CLEAN_API_H)`; \
	    echo $$line | \
		awk 'BEGIN{ FS=" "  }{ \
		    printf "%s %s %s ", $$1, $$2, $$3; \
		    v = 1; \
		    for (i = 4; i < NF; i+=3) { \
			printf "%s p%d %s", $$i, v, $$(i + 2); \
			v++; \
		    } \
		    printf "\n"; \
		    printf "{\n\tbootstrap();\n\tLOG(%s);\n\treturn funcs->%s(p1", $$2, $$2; \
		    for (i = 2; i < v; i++) printf ", p%d ", i; \
		    printf ");\n}\n"; \
		}' | sed -e 's/ ,/, /g'; \
	done; \
	) > $@

$(CLEAN_API_H): pkcs11f.h
	cpp -DCK_NEED_ARG_LIST $^ |  \
	grep -v '^#' | \
	sed -e 's/CK_PKCS11_FUNCTION_INFO[^(]*(\([^)]*\))/CK_RV \1/' | \
	awk '{if ($$1 == ");") { print line $$1; line = ""; } else line = line $$0;}' | \
	sed -e 's/,/ ,/g' | \
	sed -e 's/(/ ( /g' | \
	sed -e 's/);/ ) ;/g' | \
	sed -e 's/  [ ]*/ /g' > $@

clean:
	rm api api.c api.o pkcs11*.h pkcs11.so 
