# docker build -t pugi-builder .
# docker run --rm pugi-builder cat /src/pugi > pugi && chmod +x pugi
FROM rockylinux:8

RUN dnf install -y --enablerepo=powertools \
        make \
        clang \
        llvm \
        libbpf-devel \
        kernel-headers \
        golang \
    && dnf clean all

WORKDIR /src

COPY . .

RUN make
