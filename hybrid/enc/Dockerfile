#FROM ubuntu:20.04

FROM nimafrj/openfhe103:cpu

WORKDIR /usr/src/app
# Install dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    unzip \
    python3 \
    python3-pip \
    libgmp-dev \
    libntl-dev \
    doxygen \
    graphviz \
    build-essential \
    cmake \
    git \
    wget \
    autoconf \
    g++ \
    libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*

# RUN apt-get install -y build-essential \
#     autoconf bison gawk meson nasm pkg-config python3 python3-click \
#     python3-jinja2 python3-pyelftools python3-tomli python3-tomli-w \
#     python3-voluptuous wget

# RUN apt-get install -y cmake libprotobuf-c-dev protobuf-c-compiler \
#     protobuf-compiler python3-cryptography python3-pip python3-protobuf


WORKDIR /
RUN wget https://github.com/gramineproject/gramine/releases/download/v1.8/gramine_1.8_amd64.deb
RUN apt-get update    
RUN apt-get install -y ./gramine_1.8_amd64.deb
RUN apt-get install -f
RUN rm -f gramine_1.8_amd64.deb

RUN gramine-sgx-gen-private-key

RUN wget https://github.com/Kitware/CMake/releases/download/v3.27.6/cmake-3.27.6-linux-x86_64.sh \
    && chmod +x cmake-3.27.6-linux-x86_64.sh \
    && ./cmake-3.27.6-linux-x86_64.sh --skip-license --prefix=/usr/local \
    && rm cmake-3.27.6-linux-x86_64.sh


ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV TERM xterm-256color
RUN echo 'export PS1="\[\e[36m\](docker@\h) \[\e[1;33m\][\[\e[38;5;130m\]\$(date +%H:%M:%S)\[\e[38;5;167m\] \u:\[\e[38;5;228m\] \w\[\e[1;33m\]]\[\e[m\]\n$ "' > /root/.bashrc

WORKDIR /bdt
# Copy the source code
COPY . .


RUN cp /usr/src/app/openfhe-uniman/CMakeLists.User.txt ./CMakeLists.txt
RUN echo "find_package(Threads REQUIRED)" >> CMakeLists.txt
RUN echo "add_executable(fhe-enc enc.cpp)" >> CMakeLists.txt
RUN echo "add_executable(fhe-main main.cpp)" >> CMakeLists.txt
RUN echo "add_executable(fhe-dec dec.cpp)" >> CMakeLists.txt

RUN mkdir -p /bdt/build /bdt/build/results /bdt/build/data /bdt/build/private_data /bdt/build/timing /bdt/build/cryptocontext /bdt/build/dec_results
WORKDIR /bdt/build
RUN cmake ..
RUN make

# Compile the application
# RUN g++ -o FHE-enc FHE-enc.cpp -fopenmp -std=c++17 -lOPENFHEpke -lOPENFHEcore -pthread

# Create directories

# Set permissions
RUN chmod +x fhe-enc
RUN chmod +x fhe-main
RUN chmod +x fhe-dec

WORKDIR /bdt/
RUN mv enc_Makefile /bdt/build/enc_Makefile
RUN mv dec_Makefile /bdt/build/dec_Makefile
RUN mv dec.manifest.template /bdt/build/dec.manifest.template
RUN mv enc.manifest.template /bdt/build/enc.manifest.template
WORKDIR /bdt/build/
RUN make -f dec_Makefile clean
RUN make -f dec_Makefile SGX=1
RUN make -f enc_Makefile clean
RUN make -f enc_Makefile SGX=1

# Command to run
CMD ["bash", "-l"] 
