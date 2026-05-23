NAME=vproxy

all:
	go build -o bin/vproxy ./cmd/vproxy

clean:
	rm -rf bin/vproxy
