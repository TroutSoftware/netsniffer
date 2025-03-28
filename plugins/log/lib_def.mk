# Name of module this file defines
MODULE_NAME := log

# Folder where test cases for this module can be found
#TEST_FOLDER := 

# Include folder that should be included in the public search path
PUBLIC_INC := ./public_include


# List source (.cc) files that should be included in the build
CC_FILES := \
	log_framework.cc \
	logger_file.cc \
	logger_null.cc \
	logger_pipe.cc \
	logger_stdout.cc \
	serializer_bill.cc \
	serializer_csv.cc \
	serializer_lorth.cc \
	serializer_python.cc \
	serializer_txt.cc \


H_FILES = \
	logger_file.h \
	logger_null.h \
	logger_pipe.h \
	logger_stdout.h \
	public_include/log_framework.h \
	serializer_bill.h \
	serializer_csv.h \
	serializer_lorth.h \
	serializer_python.h \
	serializer_txt.h \

