

.PHONY: format mkrtest

SUBMAKES = $(wildcard **/makefile)

mkrtest: 
	echo $(SUBMAKES)

format:
	$(MAKE) -C ./inspectors/dhcp_monitor format
	$(MAKE) -C ./inspectors/dhcp_option format
	$(MAKE) -C ./inspectors/network_mapping format
	$(MAKE) -C ./inspectors/netflow format

