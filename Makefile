NAME=vproxy

all:
	go build -o bin/vproxy ./cmd/vproxy

clean:
	rm -rf bin/vproxy bin/test_*

build-tests:
	go build -o bin/test_direct ./tests/direct
	go build -o bin/test_upstream ./tests/upstream
	go build -o bin/test_ebpf ./tests/ebpf
	go build -o bin/test_tproxy ./tests/tproxy
	go build -o bin/test_google ./tests/google

test-network: build-tests
	@echo "=========================================="
	@echo "Running Direct Network Test..."
	@./bin/test_direct || true
	@echo "=========================================="
	@echo "Running Upstream Proxy Test..."
	@./bin/test_upstream || true
	@echo "=========================================="
