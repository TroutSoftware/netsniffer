
# Name of module this file defines
MODULE_NAME := dhcp_option

# Folder where test cases for this module can be found
TEST_FOLDER := tests

# List source (.cc) files that should be included in the build
CC_FILES := \
	flow_data.cc \
	inspector.cc \
	ips_option.cc \
	ips_option_ip_filter.cc 

# List header (.h) files that should be auto formatted with clang
H_FILES = \
	flow_data.h \
	inspector.h \
	ips_option.h \
	ips_option_ip_filter.h

