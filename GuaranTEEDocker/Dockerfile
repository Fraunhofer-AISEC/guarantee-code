# syntax=docker/dockerfile:1
FROM ubuntu:20.04 AS base

WORKDIR /GuaranTEE

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install wget make gnupg

# Install SGX-SDK
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.15/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.15.100.3.bin
RUN chmod +x sgx_linux_x64_sdk_2.15.100.3.bin
RUN printf "%s\n" "no" "/opt/intel" | ./sgx_linux_x64_sdk_2.15.100.3.bin
RUN rm sgx_linux_x64_sdk_2.15.100.3.bin

ENV SGX_SDK=/opt/intel/sgxsdk
ENV PATH=${PATH}:${SGX_SDK}/bin:${SGX_SDK}/bin/x64
ENV PKG_CONFIG_PATH=${SGX_SDK}/pkgconfig
ENV LD_LIBRARY_PATH=${SGX_SDK}/sdk_libs

# Install SGX user libraries
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update
RUN apt-get -y install libsgx-epid libsgx-quote-ex libsgx-dcap-ql libsgx-uae-service


FROM ubuntu:20.04 AS llvm-builder
WORKDIR /llvm

RUN apt-get update
RUN apt-get -y upgrade
RUN DEBIAN_FRONTEND=noninteractive TZ="Europe/Berlin" apt-get -y install tzdata
RUN apt-get -y install git ninja-build cmake lld-10 gcc g++ python3

RUN git clone --depth 1 https://github.com/Fraunhofer-AISEC/guarantee-llvm --branch guarantee --single-branch

# Install lld as linker
RUN ln -s /usr/bin/ld.lld-10 /usr/bin/ld.lld

# Build custom LLVM compiler
RUN mkdir llvm-install
RUN cd guarantee-llvm \
    && mkdir build && cd build \
    && cmake ../llvm -G Ninja \
        -DCMAKE_BUILD_TYPE="MinSizeRel" \
        -DLLVM_ENABLE_PROJECTS="clang" \
        -DCMAKE_INSTALL_PREFIX=../../llvm-install \
        -DLLVM_INCLUDE_TESTS=Off \
        -DLLVM_INCLUDE_EXAMPLES=Off \
        -DLLVM_ENABLE_BACKTRACES=Off \
        -DLLVM_TARGETS_TO_BUILD=X86 \
        -DLLVM_ENABLE_OCAMLDOC=Off \
        -DLLVM_BUILD_DOCS=Off \
        -DLLVM_OPTIMIZED_TABLEGEN=On \
        -DCLANG_INCLUDE_TESTS=Off \
        -DCLANG_BUILD_EXAMPLES=Off \
        -DLLVM_USE_LINKER=lld \
        ../llvm \
    && ninja \
    && ninja install


FROM base as guarantee
RUN DEBIAN_FRONTEND=noninteractive TZ="Europe/Berlin" apt-get -y install tzdata
RUN apt-get -y install git gcc g++ cmake ninja-build curl graphviz autoconf libtool zlib1g-dev

# Clone GuaranTEE repo
RUN git clone https://github.com/Fraunhofer-AISEC/guarantee-code

# Build SGX-OpenSSL
RUN cd guarantee-code/SGX-OpenSSL/OpenSSL_SGX/ \
    && ./sgx_openssl_setup.sh \
    && make depend \
    && make

COPY --from=llvm-builder llvm/llvm-install llvm-install


FROM guarantee as guarantee_hw
ARG SPID
ARG EPID_SUBSCRIPTION_KEY
ARG QUOTE_TYPE

WORKDIR /GuaranTEE/guarantee-code/GuaranTEE

RUN apt-get -y install python rename

# Generate EPID credential file
ENV SPID=$SPID
ENV EPID_SUBSCRIPTION_KEY=$EPID_SUBSCRIPTION_KEY
ENV QUOTE_TYPE=$QUOTE_TYPE

RUN cd ../sgx-ra-tls \
    && ./ra_tls_options.c.sh > ra_tls_options.c

# Build WolfSSl dependencies
ENV PATH="/GuaranTEE/llvm-install/bin:${PATH}"
RUN make deps
RUN make -C ../sgx-ra-tls clients

RUN make

FROM guarantee as guarantee_sim
WORKDIR /GuaranTEE/guarantee-code/GuaranTEE

RUN make SGX_MODE=SIM


# Sign server container in SGX simulation mode
FROM base as sign-srv-sim
WORKDIR /GuaranTEE
COPY --from=guarantee_sim /GuaranTEE/guarantee-code/GuaranTEE/bin ./bin
COPY --from=guarantee_sim /GuaranTEE/guarantee-code/GuaranTEE/cert ./cert

ENTRYPOINT ["./bin/app"]


# Sign server container in SGX hardware mode
FROM base as sign-srv-hw
WORKDIR /GuaranTEE
COPY --from=guarantee_hw /GuaranTEE/guarantee-code/GuaranTEE/bin ./bin
COPY --from=guarantee_hw /GuaranTEE/guarantee-code/GuaranTEE/cert ./cert

ENTRYPOINT ["./bin/app"]


# AESM container
FROM base AS aesm
ENV LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/opt/intel/sgx-aesm-service/aesm
RUN apt-get install -y libsgx-dcap-default-qpl

ENTRYPOINT ["/opt/intel/sgx-aesm-service/aesm/aesm_service", "--no-daemon"]


# Attestation client
FROM ubuntu:20.04 AS attestation-client
WORKDIR /attestation
RUN apt-get -y update
RUN apt-get -y upgrade

COPY --from=guarantee_hw /GuaranTEE/guarantee-code/sgx-ra-tls/wolfssl-client attestation-client

ENTRYPOINT ["./attestation-client"]
