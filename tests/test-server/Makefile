# claude-https Test Server Makefile
# Easy commands for managing the test infrastructure

.PHONY: help start stop restart logs certs clean test status build shell

# Colors
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

# Default target
help:
	@echo ""
	@echo "$(GREEN)claude-https Test Server$(NC)"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  $(YELLOW)start$(NC)     - Generate certs (if needed) and start all services"
	@echo "  $(YELLOW)stop$(NC)      - Stop all services"
	@echo "  $(YELLOW)restart$(NC)   - Restart all services"
	@echo "  $(YELLOW)logs$(NC)      - View logs (follow mode)"
	@echo "  $(YELLOW)certs$(NC)     - Generate/regenerate all certificates"
	@echo "  $(YELLOW)clean$(NC)     - Remove containers, volumes, and certificates"
	@echo "  $(YELLOW)test$(NC)      - Run connectivity tests"
	@echo "  $(YELLOW)status$(NC)    - Show service status"
	@echo "  $(YELLOW)build$(NC)     - Build/rebuild Docker images"
	@echo "  $(YELLOW)shell$(NC)     - Open shell in nginx container"
	@echo ""
	@echo "Test Endpoints:"
	@echo "  HTTP:          http://localhost:9080"
	@echo "  TLS 1.3 only:  https://localhost:9443"
	@echo "  TLS 1.2 only:  https://localhost:9444"
	@echo "  mTLS:          https://localhost:9445"
	@echo "  Expired cert:  https://localhost:9446"
	@echo "  Self-signed:   https://localhost:9447"
	@echo "  Wrong host:    https://localhost:9448"
	@echo "  Revoked cert:  https://localhost:9449"
	@echo "  HTTP/2 only:   https://localhost:9450"
	@echo "  Slow response: https://localhost:9451"
	@echo "  Large response:https://localhost:9452"
	@echo ""
	@echo "Proxy:"
	@echo "  No auth:       http://localhost:9128"
	@echo "  Basic auth:    http://localhost:9129 (testuser/testpassword)"
	@echo ""

# Generate certificates
certs:
	@echo "$(GREEN)Generating PKI infrastructure...$(NC)"
	@chmod +x ./pki/generate-certs.sh
	@./pki/generate-certs.sh

# Check if certs exist
.PHONY: check-certs
check-certs:
	@if [ ! -f "./pki/ca-bundle.crt" ]; then \
		echo "$(YELLOW)Certificates not found. Generating...$(NC)"; \
		$(MAKE) certs; \
	fi

# Build Docker images
build:
	@echo "$(GREEN)Building Docker images...$(NC)"
	docker compose build

# Start services
start: check-certs
	@echo "$(GREEN)Starting test services...$(NC)"
	docker compose up -d
	@echo ""
	@echo "$(GREEN)Services started!$(NC)"
	@echo ""
	@echo "Wait a few seconds for services to initialize, then run:"
	@echo "  make test"
	@echo ""
	@echo "Or view logs with:"
	@echo "  make logs"
	@echo ""

# Stop services
stop:
	@echo "$(YELLOW)Stopping test services...$(NC)"
	docker compose down

# Restart services
restart: stop start

# View logs
logs:
	docker compose logs -f

# Show status
status:
	@echo "$(GREEN)Service Status:$(NC)"
	@docker compose ps
	@echo ""
	@echo "$(GREEN)Port Status:$(NC)"
	@for port in 9080 9443 9444 9445 9446 9447 9448 9449 9450 9451 9452; do \
		if nc -z localhost $$port 2>/dev/null; then \
			echo "  Port $$port: $(GREEN)UP$(NC)"; \
		else \
			echo "  Port $$port: $(RED)DOWN$(NC)"; \
		fi; \
	done

# Run connectivity tests
test: check-certs
	@echo "$(GREEN)Running connectivity tests...$(NC)"
	@echo ""
	@echo "Testing HTTP (9080)..."
	@if curl -sf http://localhost:9080/health > /dev/null 2>&1; then \
		echo "  $(GREEN)✓ HTTP OK$(NC)"; \
	else \
		echo "  $(RED)✗ HTTP FAILED$(NC)"; \
	fi
	@echo ""
	@echo "Testing TLS 1.3 (9443)..."
	@if curl -sf --cacert ./pki/ca-bundle.crt https://localhost:9443/health > /dev/null 2>&1; then \
		echo "  $(GREEN)✓ TLS 1.3 OK$(NC)"; \
	else \
		echo "  $(RED)✗ TLS 1.3 FAILED$(NC)"; \
	fi
	@echo ""
	@echo "Testing TLS 1.2 (9444)..."
	@if curl -sf --cacert ./pki/ca-bundle.crt https://localhost:9444/health > /dev/null 2>&1; then \
		echo "  $(GREEN)✓ TLS 1.2 OK$(NC)"; \
	else \
		echo "  $(RED)✗ TLS 1.2 FAILED$(NC)"; \
	fi
	@echo ""
	@echo "Testing mTLS (9445)..."
	@if curl -sf --cacert ./pki/ca-bundle.crt \
		--cert ./pki/client-certs/valid-client.crt \
		--key ./pki/client-certs/valid-client.key \
		https://localhost:9445/health > /dev/null 2>&1; then \
		echo "  $(GREEN)✓ mTLS OK$(NC)"; \
	else \
		echo "  $(RED)✗ mTLS FAILED$(NC)"; \
	fi
	@echo ""
	@echo "Testing Expired Cert (9446) - should fail..."
	@if curl -sf --cacert ./pki/ca-bundle.crt https://localhost:9446/health > /dev/null 2>&1; then \
		echo "  $(RED)✗ UNEXPECTED SUCCESS (should have failed)$(NC)"; \
	else \
		echo "  $(GREEN)✓ Correctly rejected expired cert$(NC)"; \
	fi
	@echo ""
	@echo "Testing Self-Signed (9447) - should fail..."
	@if curl -sf --cacert ./pki/ca-bundle.crt https://localhost:9447/health > /dev/null 2>&1; then \
		echo "  $(RED)✗ UNEXPECTED SUCCESS (should have failed)$(NC)"; \
	else \
		echo "  $(GREEN)✓ Correctly rejected self-signed cert$(NC)"; \
	fi
	@echo ""
	@echo "Testing Wrong Hostname (9448) - should fail..."
	@if curl -sf --cacert ./pki/ca-bundle.crt https://localhost:9448/health > /dev/null 2>&1; then \
		echo "  $(RED)✗ UNEXPECTED SUCCESS (should have failed)$(NC)"; \
	else \
		echo "  $(GREEN)✓ Correctly rejected wrong hostname$(NC)"; \
	fi
	@echo ""
	@echo "Testing Echo Response..."
	@curl -sf --cacert ./pki/ca-bundle.crt \
		-X POST \
		-H "Content-Type: application/json" \
		-d '{"test": "data"}' \
		https://localhost:9443/ | head -20
	@echo ""
	@echo ""
	@echo "$(GREEN)Tests complete!$(NC)"

# Clean everything
clean:
	@echo "$(RED)Cleaning up...$(NC)"
	docker compose down -v --remove-orphans
	rm -rf ./pki/root-ca/*.key ./pki/root-ca/*.crt ./pki/root-ca/*.srl ./pki/root-ca/*.cnf
	rm -rf ./pki/intermediate-ca/*.key ./pki/intermediate-ca/*.crt ./pki/intermediate-ca/*.csr
	rm -rf ./pki/intermediate-ca/*.cnf ./pki/intermediate-ca/index.txt* ./pki/intermediate-ca/serial*
	rm -rf ./pki/intermediate-ca/crlnumber* ./pki/intermediate-ca/newcerts
	rm -rf ./pki/server-certs/*/*.key ./pki/server-certs/*/*.crt ./pki/server-certs/*/*.csr ./pki/server-certs/*/*.cnf
	rm -rf ./pki/client-certs/*.key ./pki/client-certs/*.crt ./pki/client-certs/*.csr
	rm -rf ./pki/client-certs/*.p12 ./pki/client-certs/*.pem ./pki/client-certs/*.cnf
	rm -rf ./pki/crl/*.crl ./pki/ca-bundle.crt ./pki/pinning-hashes.txt
	@echo "$(GREEN)Cleanup complete$(NC)"

# Open shell in nginx container
shell:
	docker compose exec nginx /bin/sh

# View specific container logs
.PHONY: logs-nginx logs-backend logs-ocsp logs-proxy
logs-nginx:
	docker compose logs -f nginx

logs-backend:
	docker compose logs -f backend

logs-ocsp:
	docker compose logs -f ocsp

logs-proxy:
	docker compose logs -f proxy

# Show certificate info
.PHONY: cert-info
cert-info:
	@echo "$(GREEN)Certificate Information:$(NC)"
	@echo ""
	@echo "Root CA:"
	@openssl x509 -in ./pki/root-ca/root-ca.crt -noout -subject -dates 2>/dev/null || echo "  Not found"
	@echo ""
	@echo "Intermediate CA:"
	@openssl x509 -in ./pki/intermediate-ca/intermediate-ca.crt -noout -subject -dates 2>/dev/null || echo "  Not found"
	@echo ""
	@echo "Valid Server Certificate:"
	@openssl x509 -in ./pki/server-certs/valid/server.crt -noout -subject -dates 2>/dev/null || echo "  Not found"
	@echo ""
	@echo "Client Certificate:"
	@openssl x509 -in ./pki/client-certs/valid-client.crt -noout -subject -dates 2>/dev/null || echo "  Not found"

# Show SPKI hashes for pinning
.PHONY: pinning-hashes
pinning-hashes:
	@echo "$(GREEN)SPKI Hashes for Certificate Pinning:$(NC)"
	@cat ./pki/pinning-hashes.txt 2>/dev/null || echo "Run 'make certs' first"

# Package for deployment to remote server
.PHONY: package
package: clean
	@echo "$(GREEN)Creating deployment package...$(NC)"
	@cd .. && tar --exclude='test-server/.git' \
		--exclude='test-server/*.tar.gz' \
		-czvf test-server.tar.gz test-server/
	@mv ../test-server.tar.gz ./
	@echo ""
	@echo "$(GREEN)Package created: test-server.tar.gz$(NC)"
	@echo ""
	@echo "To deploy on remote server:"
	@echo "  1. scp test-server.tar.gz user@server:/path/"
	@echo "  2. ssh user@server"
	@echo "  3. tar -xzf test-server.tar.gz"
	@echo "  4. cd test-server && make start"
	@echo ""
	@echo "Then on your n8n server, add to /etc/hosts:"
	@echo "  <test-server-ip>  testserver.local"
	@echo ""

# Generate certs with custom IP/hostname for remote deployment
.PHONY: certs-remote
certs-remote:
	@if [ -z "$(IP)" ]; then \
		echo "$(RED)Usage: make certs-remote IP=192.168.1.100$(NC)"; \
		echo ""; \
		echo "This generates certificates with the specified IP in the SAN."; \
		exit 1; \
	fi
	@echo "$(GREEN)Generating certificates for IP: $(IP)$(NC)"
	@TEST_SERVER_IP=$(IP) ./pki/generate-certs.sh

# Quick setup for remote deployment
.PHONY: setup-remote
setup-remote:
	@if [ -z "$(IP)" ]; then \
		echo "$(RED)Usage: make setup-remote IP=192.168.1.100$(NC)"; \
		echo ""; \
		echo "This will:"; \
		echo "  1. Generate certificates with the specified IP in the SAN"; \
		echo "  2. Start all services"; \
		echo "  3. Show connection info"; \
		exit 1; \
	fi
	@$(MAKE) certs-remote IP=$(IP)
	@$(MAKE) start
	@echo ""
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(GREEN)  Remote Setup Complete!$(NC)"
	@echo "$(GREEN)========================================$(NC)"
	@echo ""
	@echo "On your client machine, add to /etc/hosts:"
	@echo "  $(IP)  testserver.local"
	@echo ""
	@echo "Then use these URLs to test SecureWebFetch:"
	@echo "  https://testserver.local:9443  (TLS 1.3)"
	@echo "  https://testserver.local:9444  (TLS 1.2)"
	@echo "  https://testserver.local:9445  (mTLS)"
	@echo "  etc."
	@echo ""
	@echo "Or use IP directly:"
	@echo "  https://$(IP):9443"
	@echo ""
	@echo "CA Bundle path: $(shell pwd)/pki/ca-bundle.crt"
	@echo ""
