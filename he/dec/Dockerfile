#FROM ubuntu:20.04

FROM nimafrj/openfhe103:cpu

WORKDIR /usr/src/app
# Install dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    unzip \
    python3 \
    python3-pip \
    libgmp-dev \
    libntl-dev \
    doxygen \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

# Working directory

# Clone and build OpenFHE

# RUN git clone https://github.com/openfheorg/openfhe-development.git 

# WORKDIR /usr/src/app/openfhe-development

# RUN git checkout v1.0.3 && \
#     git submodule init && \
#     git submodule update && \
#     mkdir build && \
#     cd build && \
#     cmake .. -DBUILD_BENCHMARKS=OFF && \
#     make && \
#     make install && \
#     ldconfig

WORKDIR /bdt
# Copy the source code
COPY . .


RUN cp /usr/src/app/openfhe-uniman/CMakeLists.User.txt ./CMakeLists.txt
RUN echo "find_package(Threads REQUIRED)" >> CMakeLists.txt
RUN echo "add_executable(fhe-dec dec.cpp)" >> CMakeLists.txt

RUN mkdir -p /bdt/build/data /bdt/build/results /bdt/build/timing /bdt/build/cryptocontext /bdt/build/private_data
WORKDIR /bdt/build
RUN cmake ..
RUN make


# Create directories


# Set permissions
RUN chmod +x fhe-dec

# Command to run
CMD ["bash", "-l"] 