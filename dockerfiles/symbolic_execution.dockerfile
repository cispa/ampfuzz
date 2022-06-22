FROM ampfuzz:wllvm_wrapper

# reset ENV from wllvm_wrapper
ENV CC=clang
ENV CXX=clang++

ENV Z3_DIR=/usr/bin

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip \
	&& pip3 install posix-ipc==1.0.5

COPY . /src/03_symbolic_execution

# build
RUN mkdir -p /03_symbolic_execution
WORKDIR /03_symbolic_execution
RUN cmake -G Ninja \
        -DQSYM_BACKEND=OFF \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DZ3_TRUST_SYSTEM_VERSION=on \
        /src/03_symbolic_execution \
    && ninja check libcxx_symcc \
    && ninja install
