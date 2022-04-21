Control-Flow Attestation with GuaranTEE
=======================================

This is the GuaranTEE code repository which contains the code to the paper
[GuaranTEE](https://doi.org/10.48550/arXiv.2202.07380). The repository contains
the secure SSL server, the SGX-SSL project and the modified LLVM compiler
version. In order to build the project follow the instructions below. The build
instructions are tested with Ubuntu 20.04 LTS. For an easier start you can also
build the Docker images.

## Build and Run GuaranTEE

1. Install the required dependencies and clone the repository
    ```
    sudo apt-get update
    sudo apt-get install git gcc g++ make cmake ninja-build curl graphviz \
                         rename zlib1g zlib1g-dev python autoconf libtool \
                         zlib1g-dev

    git clone https://github.com/Fraunhofer-AISEC/guarantee-code
    ```

2. Install the SGX driver and the SGX SDK

    The prebuild binaries can be downloaded from Intel
    [here](https://01.org/intel-software-guard-extensions/downloads).

    If no SGX hardware is available, Guarantee can be build and tested in
    simulation mode. In this case installing the SGX SDK is sufficient. The SDK
    has to be installed in `/opt/intel`.

    Make sure that in all of the following steps the SGX SDK environment
    variables are set. Load them with `source /opt/intel/sgxsdk/environment`.

3. Build SGX-OpenSSL project
    ```
    cd SGX-OpenSSL/OpenSSL_SGX
    ./sgx_openssl_setup.sh
    make depend
    make
    ```

    Now the files `libcrypto.a` and `libssl.a` are in the folder
    `SGX-OpenSSL/OpenSSL_SGX`.

4. Build and install the modified compiler using the `ninja` build system

    Clone the modified LLVM compiler in the same directory as the GuaranTEE
    repository and create the LLVM installation directory.
    ```
    git clone https://github.com/Fraunhofer-AISEC/guarantee-llvm
    mkdir llvm-install
    ```

    Build the modified compiler
    ```
    cd guarantee-llvm
    mkdir build && cd build
    cmake ../llvm -G Ninja \
          -DCMAKE_BUILD_TYPE="MinSizeRel" \
          -DLLVM_ENABLE_PROJECTS="clang" \
          -DLLVM_TARGETS_TO_BUILD=X86 \
          -DCMAKE_INSTALL_PREFIX=../../llvm-install \
          ../llvm
    ninja
    ninja install
    ```

    In case, the compilation fails because the standard linker requires too much
    memory causing an error like `fatal error: ld terminated with signal 9
    [Killed]` use the LLVM linker `lld`:
    ```
    sudo apt-get install lld-10

    # Create symlink in /usr/bin/
    sudo ln -s /usr/bin/ld.lld-10 /usr/bin/ld.lld

    # Reconfigure build
    cmake ../llvm -G Ninja \
          -DCMAKE_BUILD_TYPE="Release" \
          -DLLVM_ENABLE_PROJECTS="clang" \
          -DLLVM_TARGETS_TO_BUILD=X86 \
          -DCMAKE_INSTALL_PREFIX=../../llvm-install \
          -DLLVM_USE_LINKER=lld \
          ../llvm

    # Continue build
    ninja
    ```

    If you prefer to use Unix Makefiles instead of the Ninja build system
    replace `-G Ninja` with `-G "Unix Makefiles"` and `ninja` with `make` in the
    commands above.

    Now the compiler binaries can be found in `llvm-install/bin` and the
    compiler passes in `llvm-install/lib`. If you choose a different
    installation directory, you need to adapt the `LLVM_BIN_PATH` variable in
    the Makefiles accordingly.

5. Build WolfSSL dependencies

    In order to use the attestation feature of Intel SGX, an API key for the
    [Intel SGX attestation
    service](https://api.portal.trustedservices.intel.com/EPID-attestation) is
    required. This example works with linkable quotes. Before the build, the
    credentials have to be included in the project. Use the primary key for the
    `EPID_SUBSCRIPTION_KEY`. In order to test GuaranTEE without attestation,
    skip step 5 and 7.
    ```
    cd sgx-ra-tls
    export SPID=0123456789abcdef0123456789abcdef
    export EPID_SUBSCRIPTION_KEY=012345679abcdef012345679abcdef
    export QUOTE_TYPE=SGX_LINKABLE_SIGNATURE
    ./ra_tls_options.c.sh > ra_tls_options.c
    ```

    Make sure the previously build compiler is added to `$PATH` by executing
    `export PATH=$PATH:/path/to/llvm-install/bin`. Then, build the dependencies
    with:
    ```
    cd GuaranTEE
    make deps
    ```

6. Build Guarantee
    ```
    cd GuaranTEE
    make
    ```

    This builds the server in hardware debug mode. To build the project in
    simulation mode replace `make` with `make SGX_MODE=SIM`. The attestation
    functionality will be not available in simulation mode.

    To build the server in hardware debug mode without attestation, replace
    `make` with `make SGX_ATTESTATION=FALSE`.

7. Build client for attestation and checking the log (theoretically from remote)

    Only necessary if attestation is enabled.
    ```
    cd sgx-ra-tls
    make clients
    ```

8. Run Guarantee
    ```
    cd GuaranTEE
    # Start ProveTEE and VerifyTEE
    ./bin/app

    # Learn benign control flows
    ./server_learn.sh

    # Send a valid request to the server
    ./sample_request.sh

    # If attestation is enabled: Read the log and the attestation of the enclave
    # via WolfSSL client
    ../sgx-ra-tls/wolfssl-client
    ```

    After the server has terminated, the request log is printed to the command
    line. The requests are marked as OK or MALICIOUS depending on whether they
    have violated the prerecorded control flow obtained in the learning phase.

    Using `server_learn_malicious.sh` instead of `server_learn.sh` causes the
    Analyzer not to learn the control flow corresponding to the request of a
    wrong file. If a wrong file (with `./sample_request_malicious.sh`) is
    requested afterwards, the corresponding request appears as MALICIOUS in the
    log.

    Terminate the server by pressing enter.

    After printing the log, the analyzer prints his internal control flow graph
    as DOT graph to the file `valid_cfg.dot` for debugging purposes. It can then
    be converted to a PDF by running `generate_graph.sh`. The control flow graph
    is then written to the file `valid_cfg.pdf`.


## Build and Run GuaranTEE with Docker
Install the [Docker Engine](https://docs.docker.com/engine/install/) and [Docker
Compose](https://docs.docker.com/compose/install/) according to the installation
guide. Make sure all Docker commands can be executed without root priviledges.

All sources and scripts can be found in the `GuaranTEEDocker` folder.

### Test GuaranTEE on Real SGX Hardware

1. Install the Intel SGX driver

    Install the Intel SGX driver. Installation of the SDK and the PSW is not
    necessary.

2. Build the Docker images

    In order to use the attestation feature of Intel SGX, an API key for the
    [Intel SGX attestation
    service](https://api.portal.trustedservices.intel.com/EPID-attestation) is
    required. This example works with linkable quotes. Before the build, the
    credentials have to be updated in `epid.config`. Use the primary key for the
    `EPID_SUBSCRIPTION_KEY`.
    ```
    SPID=0123456789abcdef0123456789abcdef
    EPID_SUBSCRIPTION_KEY=012345679abcdef012345679abcdef
    QUOTE_TYPE=SGX_LINKABLE_SIGNATURE
    ```
    You can execute `git update-index --skip-worktree epid.config` to make Git
    ignore the local changes to the configuration file.

    Afterwards, the Docker image can be build with:
    ```
    ./build_hw.sh
    ```
    This step can take a while because the modified LLVM compiler is build from
    the sources.

3. Run GuaranTEE

    ```
    ./run_hw.sh
    ```

4. Learn the control flow (either benign or malign control flow)

    Benign requests: GuaranTEE learns all valid control flows. All subsequent
    requests send to the server are shown as valid.
    ```
    ./benign_control_flow.sh
    ```

    Malign requests: GuaranTEE learns only a subset of all possible control
    flows. All requests triggering a control flow which was not learned before
    are recognized as malicious. This simulates a real attack where the attacker
    hijacks the control flow.
    ```
    ./malign_control_flow.sh
    ```

5. Send test requests to the server

    ```
    ./send_requests.sh
    ```

5. Attest the verify enclave and receive the request logs

    ```
    ./run_attestation.sh
    ```

    If GuaranTEE has learned all valid control flows (with
    `./benign_control_flow.sh`), all requests are shown as `OK`. Otherwise some
    of the requests are maked with `MALICIOUS`.


### Test GuaranTEE in Simulation Mode

1. Build the Docker images

    ```
    ./build_sim.sh
    ```
    This step can take a while because the modified LLVM compiler is build from
    the sources.

3. Run GuaranTEE

    ```
    ./run_sim.sh
    ```

4. Learn the control flow (either benign or malign control flow)

    Benign requests: GuaranTEE learns all valid control flows. All subsequent
    requests send to the server are shown as valid.
    ```
    ./benign_control_flow.sh
    ```

    Malign requests: GuaranTEE learns only a subset of all possible control
    flows. All requests triggering a control flow which was not learned before
    are recognized as malicious. This simulates a real attack where the attacker
    hijacks the control flow.
    ```
    ./malign_control_flow.sh
    ```

5. Send test requests to the server

    ```
    ./send_requests.sh
    ```

5. Receive the request logs

    Terminate the signing server by pressing any character in the terminal. The
    log is printed to the output. If GuaranTEE has learned all valid control
    flows (with `./benign_control_flow.sh`), all requests are shown as `OK`.
    Otherwise some of the requests are maked with `MALICIOUS`.


## Repository Structure
 ```
├── GuaranTEE/
|   |      (Secure SSL server implementation)
│   ├── AddressQueue/
|   |       (Implementation of the shared memory queue)
│   ├── App/
|   |       (The user space application)
│   ├── cert/
|   |       (The self signed server certificates)
│   ├── Crypto/
|   |       (Crypto and hash implementation)
|   ├── Include/
|   |       (Important header files)
│   ├── ProveTEE/
|   |       (Prover enclave including the trampoline)
│   ├── SSL-Server/
|   |       (The signing server implementation)
│   └── VerifyTEE/
|           (Verifier enclave including the analyzer)
|
├──  GuaranTEEDocker/
|           (GuaranTEE Docker container)
|
├── SGX-OpenSSL/
|   |       (OpenSSL implementation for enclaves with example code)
|   ├── OpenSSL_SGX/
|   |       (OpenSSL implementation for enclaves)
|   └── SampleCode/
|           (Code examples for a secure server and client enclave)
|
└── sgx-ra-tls/
    |       (SGX EPID attestation with integrated TLS connection)
    ├── deps/
    |       (Folder for dependencies of sgx-ra-tls)
    |
    └── wolfssl/tls
            (Folder for the wolfssl tls-client supporting attestation)
 ```
