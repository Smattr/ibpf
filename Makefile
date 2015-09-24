ibpf: interpreter.cpp
	${CXX} -W -Wall -Wextra -std=c++11 -o $@ $<

.PHONY: clean
clean:
	rm ibpf

.PHONY: example
example: ibpf sample-program
	# Run the sample program on the `ibpf` binary itself. Obviously the binary
	# won't be a valid packet, but the sample program should still run and reject
	# it.
	./ibpf --input sample-program --data ibpf
