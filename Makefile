all: build

test:
	go test -v ./...

build:
	go build ./cmd/csf/

clean:
	rm -f csf
