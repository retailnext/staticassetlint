FROM golang:latest as build

ENV CGO_ENABLED=0

WORKDIR /go/src/github.com/retailnext/staticassetlint

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go vet -v ./...

RUN go test -v ./...

RUN go build -v -trimpath -ldflags="-s -w -buildid=" -o /staticassetlint .

FROM gcr.io/distroless/static

COPY --from=build /staticassetlint /

ENTRYPOINT ["/staticassetlint"]
