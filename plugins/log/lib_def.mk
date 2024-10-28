# Name of module this file defines
MODULE_NAME := log

# Folder where test cases for this module can be found
#TEST_FOLDER := 

# Include folder that should be included in the public search path
PUBLIC_INC := ./public_include


# List source (.cc) files that should be included in the build
CC_FILES := \
	log_bill.cc \
	log_framework.cc \
	log_lorth.cc \
	log_txt.cc \
	output_to_file.cc \
	output_to_pipe.cc \
	output_to_stdout.cc \

H_FILES = \
	log_bill.h \
	log_lorth.h \
	log_txt.h \
	output_to_file.h \
	output_to_pipe.h \
	output_to_stdout.h \
	public_include/log_framework.h \

