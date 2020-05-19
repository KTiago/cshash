all: build

test:
	go test -v ./...

build:
	go build ./cmd/cshash/

install:
	go install ./cmd/cshash/

clean:
	rm -f cshash
