FROM golang:1.24 AS build

RUN apt-get update && apt-get -y install libolm3 libolm-dev && rm -rf /var/lib/apt/lists/* && apt-get clean

WORKDIR /app
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY . .
RUN go build .

FROM ubuntu:24.04
COPY --from=build /app/MatrixBot /app
COPY --from=build /usr/lib/x86_64-linux-gnu/libolm* /usr/lib/x86_64-linux-gnu

ENTRYPOINT ["/app"]
