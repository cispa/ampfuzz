all: images

images: base wllvm_wrapper fuzzer honeypot_synthesis

base: .stamps/base

wllvm_wrapper: .stamps/wllvm_wrapper

fuzzer: .stamps/fuzzer

honeypot_synthesis: .stamps/symbolic_execution

.stamps/base: dockerfiles/base.dockerfile $(shell find llvm/ -type d|sed 's/ /\\ /g')
	docker build -t 'ampfuzz:base' -f dockerfiles/base.dockerfile llvm
	mkdir -p .stamps && touch $@

.stamps/wllvm_wrapper: .stamps/base dockerfiles/wllvm_wrapper.dockerfile $(shell find 01_wllvm_wrapper/ -type d|sed 's/ /\\ /g')
	docker build -t 'ampfuzz:wllvm_wrapper' -f dockerfiles/wllvm_wrapper.dockerfile 01_wllvm_wrapper
	mkdir -p .stamps && touch $@

.stamps/fuzzer: .stamps/wllvm_wrapper dockerfiles/fuzzer.dockerfile $(shell find 02_fuzzer/ -type d|sed 's/ /\\ /g')
	docker build -t 'ampfuzz:fuzzer' -f dockerfiles/fuzzer.dockerfile 02_fuzzer
	mkdir -p .stamps && touch $@

.stamps/symbolic_execution: .stamps/wllvm_wrapper dockerfiles/symbolic_execution.dockerfile $(shell find 03_symbolic_execution/ -type d|sed 's/ /\\ /g')
	docker build -t 'ampfuzz:symbolic_execution' -f dockerfiles/symbolic_execution.dockerfile 03_symbolic_execution
	mkdir -p .stamps && touch $@