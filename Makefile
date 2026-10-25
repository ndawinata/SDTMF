.PHONY: test python js c go demo

test: python js c go

python:
	python3 python/test_sdtmf.py

js:
	node js/test.js

c:
	gcc -O2 -Wall -Wextra -Werror -I c/src \
		c/extras/test_sdtmf.c c/src/sdtmf.c c/src/sha256.c \
		-o /tmp/test_sdtmf
	/tmp/test_sdtmf

go:
	$(MAKE) -C go test

demo:
	python3 encrypt.py
