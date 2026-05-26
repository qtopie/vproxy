NAME=vproxy

all:
	go build -o bin/vproxy ./cmd/vproxy

clean:
	rm -rf bin/vproxy bin/test_*

build-tests:
	go build -o bin/test_direct ./cmd/test/direct
	go build -o bin/test_upstream ./cmd/test/upstream
	go build -o bin/test_ebpf ./cmd/test/ebpf
	go build -o bin/test_tproxy ./cmd/test/tproxy
	go build -o bin/test_google ./cmd/test/google

test-network: build-tests
	@echo "=========================================="
	@echo "Running Direct Network Test..."
	@./bin/test_direct || true
	@echo "=========================================="
	@echo "Running Upstream Proxy Test..."
	@./bin/test_upstream || true
	@echo "=========================================="
