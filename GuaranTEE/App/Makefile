#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

include ../buildenv.mk

TARGET := app

RM := rm -f
SGX_RA_TLS_ROOT := ../../sgx-ra-tls
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH)

ifneq ($(SGX_MODE), HW)
	URTS_LIB_NAME := sgx_urts_sim
	UAE_SERVICE_LIB := sgx_uae_service_sim
	App_Link_Flags += -lsgx_uae_service_sim -lsgx_urts_sim
else
	URTS_LIB_NAME := sgx_urts
	UAE_SERVICE_LIB := sgx_uae_service
    App_Link_Flags += -lsgx_uae_service -lsgx_urts
endif

ifeq ($(SGX_ATTESTATION), TRUE)
	VERTEE_EDL := VerifyTEE_att
else
	VERTEE_EDL := VerifyTEE
endif

ATTESTATION_LINK_FLAGS := -L$(SGX_RA_TLS_ROOT)/deps/local/lib $(SGX_RA_TLS_ROOT)/deps/local/lib/libcurl-wolfssl.a \
						  $(SGX_RA_TLS_ROOT)/deps/local/lib/libwolfssl.a -lz -lm
ATTESTATION_C_FLAGS := -DWOLFSSL_SGX -DUSE_WOLFSSL
ATTESTATION_INCLUDE_PATHS := -I$(WOLFSSL_ROOT)/ -I$(WOLFSSL_ROOT)/wolfcrypt/ -I$(SGX_RA_TLS_ROOT) \
							 -I$(SGX_RA_TLS_ROOT)/deps/local/include
ATTESTATION_EDGER8R_FLAGS := --search-path $(SGX_SDK)/include

INC := -I$(SGX_SDK)/include -I../AddressQueue -I../Crypto
LIB := -l$(URTS_LIB_NAME) -l$(UAE_SERVICE_LIB) -L$(SGX_SDK)/lib64 -lpthread

ifeq ($(SGX_ATTESTATION), TRUE)
	INC += $(ATTESTATION_INCLUDE_PATHS) $(ATTESTATION_C_FLAGS)
	App_Link_Flags += $(ATTESTATION_LINK_FLAGS)
	ATTESTATION_EDGER8R_FLAGS += --search-path $(SGX_RA_TLS_ROOT) --search-path ./
endif

CFLAGS += $(INC) $(LIB)

ifeq ($(SGX_DEBUG), 1)
	CFLAGS += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	CFLAGS += -DEDEBUG -DNDEBUG -UDEBUG
else
	CFLAGS += -DNDEBUG -UEDEBUG -UDEBUG
endif

SRC_C = App.c ocalls.c

ifeq ($(SGX_ATTESTATION), TRUE)
	SRC_C += ias-ra.c server-tls.c sgxsdk-ra-attester.c
endif

SRC_OBJ += $(SRC_C:.c=.o)


.PHONY = all clean

all: $(TARGET)

ProveTEE_u.o: ProveTEE_u.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

$(VERTEE_EDL)_u.o: $(VERTEE_EDL)_u.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

ProveTEE_u.c:
	@$(SGX_EDGER8R) --untrusted ../ProveTEE/ProveTEE.edl --search-path $(SGX_SDK)/include

$(VERTEE_EDL)_u.c:
	@$(SGX_EDGER8R) --untrusted ../VerifyTEE/$(VERTEE_EDL).edl $(ATTESTATION_EDGER8R_FLAGS)

$(TARGET): ProveTEE_u.o $(VERTEE_EDL)_u.o $(SRC_OBJ)
	@$(CC) $^ $(CFLAGS) -o $@ $(App_Link_Flags)
	@mv $@ $(TOPDIR)/$(OUTDIR)/
	@echo "GEN  =>  $@"

.SILENT: $(SRC_OBJ)

clean:
	@$(RM) $(TARGET) *_u.c *_u.h *.o
