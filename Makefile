ibpf: interpreter.cpp
	${CXX} -W -Wall -Wextra -std=c++11 -o $@ $<

.PHONY: clean
clean:
	rm ibpf
