CHANGE_DIR = cd ./pythonx/completers/javascript && 
HAS_YARN := $(shell which yarn)

js:
ifdef HAS_YARN
	$(CHANGE_DIR) yarn install
else
	$(CHANGE_DIR) npm install
endif


.PHONY: js

test:
	pytest pythonx/completers/tiger_utils.py

logs:
	tail -f pythonx/completor.log
