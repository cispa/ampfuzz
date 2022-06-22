FROM ampfuzz:base

COPY . /src/01_wllvm_wrapper

RUN mkdir /01_wllvm_wrapper

WORKDIR /01_wllvm_wrapper

RUN cmake /src/01_wllvm_wrapper && make -j $(nproc) && make -j $(nproc) install

ENV CC=/01_wllvm_wrapper/pre_clang
ENV CXX=/01_wllvm_wrapper/pre_clang++