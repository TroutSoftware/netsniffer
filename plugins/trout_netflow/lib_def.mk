
# Name of module this file defines
MODULE_NAME := trout_netflow

# Folder where test cases for this module can be found
TEST_FOLDER := tests

# List source (.cc) files that should be included in the build

CC_FILES := \
	alert_lioli.cc \
	flow_data.cc \
	inspector.cc \
	ips_lioli_bind.cc \
	ips_lioli_tag.cc \
	trout_netflow.cc \
	trout_netflow_data.cc

H_FILES = \
	alert_lioli.h \
	flow_data.h \
	ips_lioli_bind.h \
	ips_lioli_tag.h \
	trout_netflow.h \
	trout_netflow.private.h \
	trout_netflow_data.h

