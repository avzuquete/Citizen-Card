CXX_PTEID_INC_DIR = /usr/local/include
CXX_PTEID_LIB_DIR = /usr/local/lib

PTEID_BIN_DIR = /usr/local/bin
CRYPTOKI_INC_DIR = /usr/include/opencryptoki
X509_INC_DIR = /usr/include/openssl

CXX = g++
CXXFLAGS = -I$(CXX_PTEID_INC_DIR) -I$(CRYPTOKI_INC_DIR) -I$(X509_INC_DIR) -g -Wpedantic -Wall -Wextra -Wconversion

all: CCdump

CCdump: ccdump.o ccerrors.o
	$(CXX) -o $@ $^ -L$(CXX_PTEID_LIB_DIR) -lpteidlib -lpteidpkcs11 -lcrypto -g

%.o: %.cxx
	$(CXX) $(CXXFLAGS) -c -o $@ $*.cxx

ccdump.o: ccdump.cxx $(CXX_PTEID_INC_DIR)/eidlib.h $(CRYPTOKI_INC_DIR)/pkcs11.h $(X509_INC_DIR)/x509.h

$(CXX_PTEID_INC_DIR)/eidlib.h:
	@echo "Please install the PTEID package"

$(CRYPTOKI_INC_DIR)/pkcs11.h:
	@echo "Please install the libopencryptoki-dev package"

$(X509_INC_DIR)/pkcs11.h:
	@echo "Please install the libssl-dev package"

eidstore:
	cp -R $(PTEID_BIN_DIR)/$@ .

clean:
	-rm *.o
	-rm CCdump
	-rm -rf eidstore
