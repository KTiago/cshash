all: build

test:
	go test -v ./...

build:
	go build ./cmd/cshash/

clean:
	rm -f cshash
