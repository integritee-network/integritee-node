FROM phusion/baseimage:focal-1.0.0
LABEL maintainer="zoltan@integritee.network"
LABEL description="This is the 2nd stage: a very small image where we copy the Substrate binary."

RUN mv /usr/share/ca* /tmp && \
	rm -rf /usr/share/*  && \
	mv /tmp/ca-certificates /usr/share/ && \
	useradd -m -u 1000 -U -s /bin/sh -d /integritee integritee && \
	mkdir -p /integritee/.local/share/integritee-node && \
	chown -R integritee:integritee /integritee/.local && \
	ln -s /integritee/.local/share/integritee-node /data

# install netcat for healthcheck
RUN apt-get update && apt-get install -yq netcat

COPY integritee-node /usr/local/bin
RUN chmod +x /usr/local/bin/integritee-node

# checks
RUN ldd /usr/local/bin/integritee-node && \
	/usr/local/bin/integritee-node --version

# Shrinking
#RUN rm -rf /usr/lib/python* && \
#	rm -rf /usr/bin /usr/sbin /usr/share/man

#USER integritee
EXPOSE 30333 9933 9944 9615
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/integritee-node"]