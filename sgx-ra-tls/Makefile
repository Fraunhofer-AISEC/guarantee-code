# Makefile to build non-SGX-SDK-based RA-TLS client and server
# programs.

export SGX_SDK?=/opt/intel/sgxsdk

CFLAGS+=-std=gnu99 -I. -I$(SGX_SDK)/include -Ideps/local/include $(SGX_DCAP_INC) -fPIC
CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow
CFLAGS+=$(CFLAGSERRORS) -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS+=-DSGX_GROUP_OUT_OF_DATE

# On Ubuntu 18.04 executables are built as position independent
# executables (PIE) by default. Position independent executables give
# Graphene trouble. Once this is fixed, we can potentially remove this
# link flag again.

LIBS=wolfssl/libra-challenger.a

EXECS=wolfssl-client

.PHONY: all
all: $(LIBS)

WOLFSSL_CLIENT_LIBS=-l:libra-challenger.a -l:libwolfssl.a -lm
wolfssl-client: wolfssl/tls/client-tls.c wolfssl/libra-challenger.a
	$(CC) -o $@ $(filter %.c, $^) $(CFLAGS) -Lwolfssl -Ldeps/local/lib $(WOLFSSL_CLIENT_LIBS)

ra_tls_options.c: ra_tls_options.c.sh
	bash $^ > /dev/null


wolfssl/libra-challenger.a: wolfssl ra.o wolfssl-ra-challenger.o wolfssl-ra.o ra-challenger.o ias_sign_ca_cert.o
	$(AR) rcs $@ $(filter %.o, $^)

libsgx_ra_tls_wolfssl.a:
	make -f ratls-wolfssl.mk
	rm -f wolfssl-ra-challenger.o wolfssl-ra.o ra-challenger.o ias_sign_ca_cert.o  # BUGFIX: previous Makefile compiles these .o files with incorrect C flags


%.html: %.md
	pandoc --from markdown_github --to html --standalone $< --output $@

.PHONY: html
html: README.html README-ECDSA.html

clients: wolfssl-client
sgxsdk-server: deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a libsgx_ra_tls_wolfssl.a

clean:
	$(RM) *.o
	$(RM) $(LIBS)
	$(RM) ecdsa-sample-data/real/sample_data.h
	$(RM) ecdsa-attestation-collateral.c ecdsa-attestation-collateral.h
	$(RM) wolfssl-client

mrproper: clean
	$(MAKE) -f ratls-wolfssl.mk mrproper
	$(MAKE) -C wolfssl/tls clean
	$(RM) $(EXECS) $(LIBS)
	$(RM) -rf deps
	$(RM) -r openssl-ra-challenger wolfssl-ra-challenger openssl-ra-attester wolfssl-ra-attester
	$(RM) messages.pb-c.h messages.pb-c.c ecdsa-aesmd-messages.pb-c.c ecdsa-aesmd-messages.pb-c.h

.PHONY = all clean clients scone-server scone-wolfssl-ssl-server graphene-server sgxsdk-server mrproper


.PHONY: deps
deps: deps/local/lib/libcurl-openssl.a deps/local/lib/libcurl-wolfssl.a

deps/openssl/config:
	cd deps && git clone https://github.com/openssl/openssl.git
	cd deps/openssl && git checkout OpenSSL_1_0_2g
	cd deps/openssl && ./config --prefix=$(shell readlink -f deps/local) no-shared -fPIC

deps/local/lib/libcrypto.a: deps/openssl/config
	cd deps/openssl && $(MAKE) && $(MAKE) -j1 install

deps/wolfssl/configure:
	cd deps && git clone https://github.com/wolfSSL/wolfssl
	cd deps/wolfssl && git checkout 9f6a963c6070639a0d1f0cb58a33918d69887586
	cd deps/wolfssl && patch -p1 < ../../wolfssl_new_patch2
	cd deps/wolfssl && ./autogen.sh

# Add --enable-debug to ./configure for debug build
# WOLFSSL_ALWAYS_VERIFY_CB ... Always call certificate verification callback, even if verification succeeds
# KEEP_OUR_CERT ... Keep the certificate around after the handshake
# --enable-tlsv10 ... required by libcurl
# 2019-03-19 removed --enable-intelasm configure flag. The Celeron NUC I am developing this, does not support AVX.
WOLFSSL_CFLAGS+=-DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT
WOLFSSL_CONFIGURE_FLAGS+=--prefix=$(shell readlink -f deps/local) --enable-writedup --enable-static --enable-keygen --enable-certgen --enable-certext --with-pic --disable-examples --disable-crypttests --enable-aesni --enable-tlsv10
ifdef DEBUG
WOLFSS_CFLAGS+=--enable-debug
endif

deps/local/lib/libwolfssl.a: CFLAGS+= $(WOLFSSL_CFLAGS)
deps/local/lib/libwolfssl.a: deps/wolfssl/configure
	cd deps/wolfssl && CC=cc CFLAGS="$(CFLAGS)" ./configure $(WOLFSSL_CONFIGURE_FLAGS)
	cd deps/wolfssl && $(MAKE) install

# Ideally, deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a and
# deps/local/lib/libwolfssl.a could be built in parallel. Does not
# work however. Hence, the dependency forces a serial build.
#
# -DFP_MAX_BITS=8192 required for RSA keys > 2048 bits to work
deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a: deps/local/lib/libwolfssl.a
	cd deps/wolfssl/IDE/LINUX-SGX && make -f sgx_t_static.mk CFLAGS="-DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192"

deps/local/lib/libwolfssl.sgx.static.lib.a: deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a
	mkdir -p deps/local/lib && cp deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a deps/local/lib

deps/local/lib/libwolfssl.sgx.static.lib.a: deps/local/lib/libwolfssl.a

deps/curl/configure:
	cd deps && git clone https://github.com/curl/curl.git
	cd deps/curl && git checkout curl-7_47_0
	cd deps/curl && ./buildconf

CURL_CONFFLAGS=--prefix=$(shell readlink -f deps/local) --without-libidn --without-librtmp --without-libssh2 --without-libmetalink --without-libpsl --disable-ldap --disable-ldaps --disable-shared
ifdef DEBUG
CURL_CONFFLAGS+=--enable-debug
endif

deps/local/lib/libcurl-wolfssl.a: deps/curl/configure deps/local/lib/libwolfssl.a
	cp -a deps/curl deps/curl-wolfssl
	cd deps/curl-wolfssl && CFLAGS="-fPIC" ./configure $(CURL_CONFFLAGS) --without-ssl --with-cyassl=$(shell readlink -f deps/local)
	cd deps/curl-wolfssl && $(MAKE)
	cp deps/curl-wolfssl/lib/.libs/libcurl.a deps/local/lib/libcurl-wolfssl.a

deps/local/lib/libcurl-openssl.a: deps/curl/configure deps/local/lib/libcrypto.a
	cp -a deps/curl deps/curl-openssl
	cd deps/curl-openssl && CFLAGS="-fPIC" LIBS="-ldl -lpthread" ./configure $(CURL_CONFFLAGS) --with-ssl=$(shell readlink -f deps/local)
	cd deps/curl-openssl && $(MAKE) && $(MAKE) install
	rename 's/libcurl/libcurl-openssl/' deps/local/lib/libcurl.*

