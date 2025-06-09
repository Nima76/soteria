FROM nvidia/cuda:12.6.0-devel-ubuntu22.04

# Set terminal to non-interactive
ENV DEBIAN_FRONTEND=noninteractive

# Set the working directory inside the container
WORKDIR /usr/src/app

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    git \
    g++ \
    make \
    libboost-all-dev \
    wget  # Needed for downloading CMake

# Install CMake 3.27.6
RUN wget https://github.com/Kitware/CMake/releases/download/v3.27.6/cmake-3.27.6-linux-x86_64.sh \
    && chmod +x cmake-3.27.6-linux-x86_64.sh \
    && ./cmake-3.27.6-linux-x86_64.sh --skip-license --prefix=/usr/local \
    && rm cmake-3.27.6-linux-x86_64.sh

# Clone the accelerated OpenFHE from UNIMAN
WORKDIR /usr/src/app
RUN git clone https://github.com/beehive-lab/openfhe-uniman.git
WORKDIR openfhe-uniman
RUN git switch opt

# Build and install OpenFHE
RUN mkdir build &&\
	cd build

RUN cmake -DCMAKE_BUILD_TYPE=Debug \
          -DWITH_OPENMP=OFF \
          -DWITH_CUDA=ON \
          -DCUDA_PATH=/usr/local/cuda \
          -DCUDA_TOOLKIT_ROOT_DIR=/usr/local/cuda \
          -DCMAKE_CUDA_COMPILER=/usr/local/cuda/bin/nvcc \
          -S /usr/src/app/openfhe-uniman \
          -B /usr/src/app/openfhe-uniman/cmake-build-debug-cuda

RUN cmake --build /usr/src/app/openfhe-uniman/cmake-build-debug-cuda \
          -- -j $(nproc)

RUN cmake --install /usr/src/app/openfhe-uniman/cmake-build-debug-cuda

# Set the library path
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Command to run the compiled binary (replace 'your_binary_name' with the actual binary name)
ENV TERM xterm-256color
RUN echo 'export PS1="\[\e[36m\](docker@\h) \[\e[1;33m\][\[\e[38;5;130m\]\$(date +%H:%M:%S)\[\e[38;5;167m\] \u:\[\e[38;5;228m\] \w\[\e[1;33m\]]\[\e[m\]\n$ "' > /root/.bashrc

WORKDIR /

CMD ["bash", "-l"] 