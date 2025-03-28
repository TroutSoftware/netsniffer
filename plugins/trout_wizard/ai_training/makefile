
.PHONY: wizard_training

LOCAL_MAKE_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

wizard_training: $(DEBUG_MODULE)
	@echo MAKEDIR: $(LOCAL_MAKE_DIR)
	cd $(LOCAL_MAKE_DIR); $(SNORT) -v -c ftp.lua $(SNORT_DAQ_INCLUDE_OPTION) --plugin-path $(DEBUGDIR) -r pcaps/wireshark_ftp_only.pcap --warn-all
	cd $(LOCAL_MAKE_DIR); $(SNORT) -v -c snmp.lua $(SNORT_DAQ_INCLUDE_OPTION) --plugin-path $(DEBUGDIR) -r pcaps/snmp_only.pcap --warn-all
	cd $(LOCAL_MAKE_DIR); $(SNORT) -v -c ssh.lua $(SNORT_DAQ_INCLUDE_OPTION) --plugin-path $(DEBUGDIR) -r pcaps/wireshark_ssh.pcap --warn-all

