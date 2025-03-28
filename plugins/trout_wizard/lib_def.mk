# Name of module this file defines
MODULE_NAME := trout_wizard

# Folder where test cases for this module can be found
TEST_FOLDER := tests

# our extensions to make
LOCAL_MAKEFILE := ai_training/makefile

# Include folder that should be included in the public search path
#PUBLIC_INC := ./public_include


# List source (.cc) files that should be included in the build
CC_FILES := \
	inspector.cc \
	module.cc \


H_FILES = \
	inspector.h \
	module.h \
	plugin_def.h \
	
