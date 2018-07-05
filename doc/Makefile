all: govpn.info govpn.html

MAKEINFO ?= makeinfo

handshake.utxt: handshake.txt
	plantuml -tutxt handshake.txt

govpn.info: *.texi handshake.utxt
	$(MAKEINFO) -o govpn.info index.texi

CSS != cat style.css

govpn.html: *.texi handshake.utxt
	rm -f govpn.html/*.html
	$(MAKEINFO) --html \
		--set-customization-variable CSS_LINES='$(CSS)' \
		--set-customization-variable SHOW_TITLE=0 \
		--set-customization-variable USE_ACCESSKEY=0 \
		--set-customization-variable DATE_IN_HEADER=1 \
		--set-customization-variable TOP_NODE_UP_URL=index.html \
		--set-customization-variable CLOSE_QUOTE_SYMBOL=\" \
		--set-customization-variable OPEN_QUOTE_SYMBOL=\" \
		-o govpn.html index.texi
	cp -r .well-known govpn.html/
