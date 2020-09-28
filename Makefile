# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: gmos android ios gmos-cross evm all test clean
.PHONY: gmos-linux gmos-linux-386 gmos-linux-amd64 gmos-linux-mips64 gmos-linux-mips64le
.PHONY: gmos-linux-arm gmos-linux-arm-5 gmos-linux-arm-6 gmos-linux-arm-7 gmos-linux-arm64
.PHONY: gmos-darwin gmos-darwin-386 gmos-darwin-amd64
.PHONY: gmos-windows gmos-windows-386 gmos-windows-amd64

GOBIN = ./build/bin
GO ?= latest
GORUN = env GO111MODULE=on go run

gmos:
	$(GORUN) build/ci.go install ./cmd/gmos
	@echo "Done building."
	@echo "Run \"$(GOBIN)/gmos\" to launch gmos."

all:
	$(GORUN) build/ci.go install

android:
	$(GORUN) build/ci.go aar --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/gmos.aar\" to use the library."

ios:
	$(GORUN) build/ci.go xcode --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/Gmos.framework\" to use the library."

test: all
	$(GORUN) build/ci.go test

lint: ## Run linters.
	$(GORUN) build/ci.go lint

clean:
	env GO111MODULE=on go clean -cache
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/kevinburke/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go get -u github.com/golang/protobuf/protoc-gen-go
	env GOBIN= go install ./cmd/abigen
	@type "npm" 2> /dev/null || echo 'Please install node.js and npm'
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

# Cross Compilation Targets (xgo)

gmos-cross: gmos-linux gmos-darwin gmos-windows gmos-android gmos-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/gmos-*

gmos-linux: gmos-linux-386 gmos-linux-amd64 gmos-linux-arm gmos-linux-mips64 gmos-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-*

gmos-linux-386:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/gmos
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep 386

gmos-linux-amd64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/gmos
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep amd64

gmos-linux-arm: gmos-linux-arm-5 gmos-linux-arm-6 gmos-linux-arm-7 gmos-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep arm

gmos-linux-arm-5:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./cmd/gmos
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep arm-5

gmos-linux-arm-6:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./cmd/gmos
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep arm-6

gmos-linux-arm-7:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./cmd/gmos
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep arm-7

gmos-linux-arm64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./cmd/gmos
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep arm64

gmos-linux-mips:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/gmos
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep mips

gmos-linux-mipsle:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/gmos
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep mipsle

gmos-linux-mips64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/gmos
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep mips64

gmos-linux-mips64le:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/gmos
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/gmos-linux-* | grep mips64le

gmos-darwin: gmos-darwin-386 gmos-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/gmos-darwin-*

gmos-darwin-386:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/gmos
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-darwin-* | grep 386

gmos-darwin-amd64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/gmos
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-darwin-* | grep amd64

gmos-windows: gmos-windows-386 gmos-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/gmos-windows-*

gmos-windows-386:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./cmd/gmos
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-windows-* | grep 386

gmos-windows-amd64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./cmd/gmos
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/gmos-windows-* | grep amd64
