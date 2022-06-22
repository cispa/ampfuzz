FROM ampfuzz:wllvm_wrapper

# reset ENV from wllvm_wrapper
ENV CC=clang
ENV CXX=clang++

# prime rust crate cache
COPY ./Cargo.toml /src/02_fuzzer/
COPY ./Cargo.lock /src/02_fuzzer/
COPY ./common/Cargo.toml /src/02_fuzzer/common/
COPY ./fuzzer/Cargo.toml /src/02_fuzzer/fuzzer/
COPY ./runtime/Cargo.toml /src/02_fuzzer/runtime/
COPY ./runtime_common/Cargo.toml /src/02_fuzzer/runtime_common/
COPY ./runtime_fast/Cargo.toml /src/02_fuzzer/runtime_fast/
RUN mkdir -p /src/02_fuzzer/common/src/ && touch /src/02_fuzzer/common/src/lib.rs \
    && mkdir -p /src/02_fuzzer/fuzzer/src/ && touch /src/02_fuzzer/fuzzer/src/lib.rs \
    && mkdir -p /src/02_fuzzer/runtime/src/ && touch /src/02_fuzzer/runtime/src/lib.rs \
    && mkdir -p /src/02_fuzzer/runtime_common/src/ && touch /src/02_fuzzer/runtime_common/src/lib.rs \
    && mkdir -p /src/02_fuzzer/runtime_fast/src/ && touch /src/02_fuzzer/runtime_fast/src/lib.rs
RUN cd /src/02_fuzzer && cargo fetch

COPY . /src/02_fuzzer

# build
RUN mkdir -p /02_fuzzer
WORKDIR /02_fuzzer
RUN cmake /src/02_fuzzer && make -j $(nproc) && make -j $(nproc) install