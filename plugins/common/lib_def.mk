# Name of module this file defines
MODULE_NAME := common

# Folder where test cases for this module can be found
#TEST_FOLDER := 

# Include folder that should be included in the public search path
PUBLIC_INC := .


# List source (.cc) files that should be included in the build
CC_FILES := \
	dictionary.cc \
	lioli.cc \
	lioli_path.cc \

H_FILES = \
	dictionary.h \
	lioli.h \
	lioli_path.h \
	lioli_tree_generator.h \
	testable_time.h
