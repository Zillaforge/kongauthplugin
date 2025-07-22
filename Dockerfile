FROM busybox
COPY build/kong-auth-plugin /home/plugins/
WORKDIR /home/plugins
