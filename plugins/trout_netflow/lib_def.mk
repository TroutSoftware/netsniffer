
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
	lioli.cc \
	log_bill.cc \
	log_framework.cc \
	log_lorth.cc \
	log_txt.cc \
	output_to_file.cc \
	output_to_pipe.cc \
	output_to_stdout.cc \
	trout_netflow.cc \
	trout_netflow_data.cc

H_FILES = \
	alert_lioli.h \
	flow_data.h \
	ips_lioli_bind.h \
	lioli.h \
	lioli_tree_generator.h \
	log_bill.h \
	log_framework.h \
	log_lorth.h \
	log_txt.h \
	output_to_file.h \
	output_to_pipe.h \
	output_to_stdout.h \
	trout_netflow.h \
	trout_netflow.private.h \
	trout_netflow_data.h

