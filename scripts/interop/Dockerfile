# Interop harness image (linux/amd64): the official CIE middleware's PKCS#11 module built from source, OpenCIE's
# released module, pcsc-lite with vsmartcard's vpcd virtual reader, and Go. The repository is mounted at /src when
# the image runs; see run.sh.

FROM --platform=linux/amd64 debian:bookworm AS official
ARG CIE_MW_COMMIT=a05337fc3ea3a526e6f173634c0f5ed0eb059859
# libcryptopp.a is stored in Git LFS, so it is fetched separately and checked against the LFS pointer's hash.
ARG CRYPTOPP_SHA256=48c74132c759246c53ebe9e957a39c3af7876e41e5a9a4b2ff1047506c461dbf
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates cmake curl libpcsclite-dev \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir /cie && curl -fsSL https://github.com/italia/cie-middleware-linux/archive/${CIE_MW_COMMIT}.tar.gz \
    | tar -xz -C /cie --strip-components=1 \
    && curl -fsSL -o /cie/cie-pkcs11/libcryptopp.a \
    https://media.githubusercontent.com/media/italia/cie-middleware-linux/${CIE_MW_COMMIT}/cie-pkcs11/libcryptopp.a \
    && echo "${CRYPTOPP_SHA256}  /cie/cie-pkcs11/libcryptopp.a" | sha256sum -c -
COPY build-official.sh /usr/local/bin/
RUN build-official.sh /cie /libcie-pkcs11.so

# vpcd from source: the Debian package (3.3) does not answer SCARD_ATTR_ATR_STRING, which the official middleware
# reads the ATR with.
FROM --platform=linux/amd64 debian:bookworm AS vpcd
ARG VSMARTCARD_COMMIT=93286a90d2411120ae17299f9902e1fdd8954185
RUN apt-get update && apt-get install -y --no-install-recommends autoconf automake build-essential ca-certificates curl \
    help2man libpcsclite-dev libtool pkg-config python3 && rm -rf /var/lib/apt/lists/*
RUN mkdir /vs && curl -fsSL https://github.com/frankmorgner/vsmartcard/archive/${VSMARTCARD_COMMIT}.tar.gz \
    | tar -xz -C /vs --strip-components=1 \
    && cd /vs/virtualsmartcard && autoreconf --install && ./configure --sysconfdir=/etc \
    && make -C src/vpcd && make -C src/ifd-vpcd && make -C src/ifd-vpcd install DESTDIR=/out \
    && mkdir /vpcd && cp -L /out/usr/lib/pcsc/drivers/serial/libifdvpcd.so /vpcd/ && cp /out/etc/reader.conf.d/vpcd /vpcd/reader.conf

FROM --platform=linux/amd64 golang:1.26-bookworm
ARG OPENCIE_VERSION=1.3.3
RUN apt-get update && apt-get install -y --no-install-recommends curl libpcsclite-dev openssl pcscd pcsc-tools \
    && rm -rf /var/lib/apt/lists/*
COPY --from=vpcd /vpcd/libifdvpcd.so /usr/lib/pcsc/drivers/serial/libifdvpcd.so
COPY --from=vpcd /vpcd/reader.conf /etc/reader.conf.d/vpcd
COPY --from=official /libcie-pkcs11.so /usr/local/lib/libcie-pkcs11.so
RUN cd /tmp && base=https://github.com/M0Rf30/opencie-pkcs11/releases/download/${OPENCIE_VERSION} \
    && file=libopencie-pkcs11-${OPENCIE_VERSION}-linux-x86_64.so \
    && curl -fsSLO ${base}/${file} && curl -fsSLO ${base}/SHA256SUMS \
    && grep " ${file}\$" SHA256SUMS | sha256sum -c - \
    && mv ${file} /usr/local/lib/libopencie-pkcs11.so && rm SHA256SUMS
ENV CIE_MW_MODULE=/usr/local/lib/libcie-pkcs11.so OPENCIE_MODULE=/usr/local/lib/libopencie-pkcs11.so
WORKDIR /src
