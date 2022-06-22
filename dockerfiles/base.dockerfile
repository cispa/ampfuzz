FROM debian:bullseye

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

# get LLVM-11
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y \
        llvm-11-dev \
        clang-11 \
        libblocksruntime-dev

# get other tools
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y \
        cmake \
        cargo \
        zlib1g-dev \
        python-is-python3 \
        ninja-build \
        zsh \
        libtirpc-dev \
        libsystemd-dev \
        git \
        devscripts \
        python3-pip \
        vim \
        tcpdump \
        net-tools \
        netcat \
        ncat \
        libz3-dev \
        apt-utils && \
    apt-get clean

# add source repositories, prefer local repositories
RUN cp /etc/apt/sources.list /etc/apt/sources.list~ && \
    mv /etc/apt/sources.list /etc/apt/sources.list.d/99_default.list && \
    sed 's/deb /deb-src /' /etc/apt/sources.list.d/99_default.list > /etc/apt/sources.list.d/99_debsrc.list && \
    echo "" > /etc/apt/sources.list && \
    echo 'Package: *\nPin: origin ""\nPin-Priority: 9999' > /etc/apt/preferences.d/prefer_local && \
    echo 'APT::Install-Recommends "0";\nAPT::Install-Suggests "0";' > /etc/apt/apt.conf.d/01norecommend && \
    apt-get update

# create non-root user
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y sudo && useradd user && echo "user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-user
# prevent env_reset and secure_path
RUN sed -Ei 's/^(Defaults\s+)env_reset$/\1!env_reset/g' /etc/sudoers && \
    sed -Ei 's/^(Defaults\s+)secure_path.*$/\1!secure_path/g' /etc/sudoers

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get -y install debconf-utils && \
    echo resolvconf resolvconf/linkify-resolvconf boolean false | debconf-set-selections && \
    apt-get -y install resolvconf

# add zsh to path
ENV PATH="/usr/bin/zsh:${PATH}"

# add llvm to path,
# but do not take precedence
ENV PATH="$PATH:/usr/lib/llvm-11/bin"

# install extra tools
RUN pip3 install wllvm
ENV LLVM_COMPILER_PATH=/usr/lib/llvm-11/bin

# prepare llvm source (needed by all other stages)
COPY . /src/llvm
