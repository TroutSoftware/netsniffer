

.PHONY: format

format:
	$(MAKE) -C ./inspectors/network_mapping format
	$(MAKE) -C ./inspectors/dhcp_monitor format
	$(MAKE) -C ./inspectors/dhcp_option format


