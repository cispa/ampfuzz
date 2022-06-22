FROM debian:bullseye

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

RUN DEBIAN_FRONTEND=noninteractive \
    apt update && \
    apt -y upgrade && \
    apt -y install file

RUN mkdir /eval/
COPY check.sh /eval/
WORKDIR /eval/
ENTRYPOINT ["/bin/bash"]
CMD ["check.sh"]
