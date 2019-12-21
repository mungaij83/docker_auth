FROM busybox
# Application
MAINTAINER "mungaij83@gmail.com"
LABEL description="Harbour living API"
LABEL version="0.0.1"
#
ENV APP_WORKDIR /app
run echo $APP_WORKDIR
ADD /bin $APP_WORKDIR
WORKDIR $APP_WORKDIR
# Config file to be passed to application overide with volumes
CMD ["/config/auth_config.yml"]
# External access port
EXPOSE 5001
run ls -al /app
# Entry point app
ENTRYPOINT ["/app/auth_server"]
