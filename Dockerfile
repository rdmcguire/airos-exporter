FROM image.libretechconsulting.com/library/golang:latest AS build
WORKDIR /go/src/app
ENV GO111MODULE=auto CGO_ENABLED=0
COPY . .
RUN go build

FROM image.libretechconsulting.com/library/alpine:latest
WORKDIR /app
COPY --from=build /go/src/app /app
ENTRYPOINT [ "./airos-stats" ]
