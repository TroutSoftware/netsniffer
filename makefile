
# OUR SNORT MODULE DEFINITIONS
MODULE_NAME := trout_snort
RELEASEDIR := $(abspath p/release)
DEBUGDIR := $(abspath p/debug)
MAKEDIR := $(abspath .m)

DEBUG_MODULE := $(DEBUGDIR)/$(MODULE_NAME).so
RELEASE_MODULE := $(RELEASEDIR)/$(MODULE_NAME).so

# SNORT3 DEFINTIONS (used for dev builds of snort)
SNORT3_TAG := 3.3.2.0
LIBML_TAG := 1.1.0
LIBDAQ_TAG := v3.0.16

DEPS_FOLDER := $(abspath deps)
DEV_FOLDER := $(DEPS_FOLDER)/dev

SNORT3_FOLDER := $(DEPS_FOLDER)/snort3-$(SNORT3_TAG)
SNORT3_FILE := $(DEPS_FOLDER)/snort3-$(SNORT3_TAG).tar.gz
SNORT3_INSTALL_FOLDER := $(DEPS_FOLDER)/install/snort3-$(SNORT3_TAG)
LIBML_FOLDER := $(DEPS_FOLDER)/libml-$(LIBML_TAG)
LIBML_FILE := $(DEPS_FOLDER)/libml-$(LIBML_TAG).tag.gz
LIBML_INSTALL_FOLDER := $(DEPS_FOLDER)/install/libml-$(LIBML_TAG)
LIBDAQ_FOLDER := $(DEPS_FOLDER)/libdaq-3.0.16
LIBDAQ_FILE := $(DEPS_FOLDER)/libdaq.$(LIBDAQ_TAG).tag.gz
LIBDAQ_INSTALL_FOLDER := $(DEPS_FOLDER)/install/libdaq-$(LIBDAQ_TAG)

# DEPENDENCIES WE HAVE (used for packaging and development)
UBUNTU_RUN_TIME_DEPS := libhwloc15 libdumbnet1 libluajit-5.1-2 libpcap0.8t64 libpcre3
UBUNTU_DEV_TIME_DEPS := make libarchive-tools dh-autoreconf cmake g++ pkgconf libdumbnet-dev flex libhwloc-dev libluajit-5.1-dev libssl-dev libpcap-dev libpcre3-dev libarchive-dev libmnl-dev clang-format

# DEFINE WHICH SNORT3 TO USE IN REST OF MAKEFILE
SYSTEM_SNORT_INCLUDE := /opt/snort/include/snort
SYSTEM_SNORT_BINARY := /opt/snort/bin/snort

DEV_SNORT_INCLUDE := $(DEV_FOLDER)/include/snort
DEV_SNORT_BINARY := $(DEV_FOLDER)/bin/snort
DEV_SNORT_LIBRARY := $(DEV_FOLDER)/lib:$(DEV_FOLDER)/lib/snort/:$(DEV_FOLDER)/lib/snort/daq

ifneq ($(wildcard $(DEV_SNORT_BINARY)),)
	SNORT := $(DEV_SNORT_BINARY)
	LD_LIBRARY_PATH := $(DEV_SNORT_LIBRARY)
	export LD_LIBRARY_PATH
	export SNORT_DAQ_PATH = $(DEV_FOLDER)/lib/daq
	SNORT_DAQ_INCLUDE_OPTION = --daq-dir $(DEV_FOLDER)/lib/daq 
else
	SNORT := $(SYSTEM_SNORT_BINARY)
endif

export SNORT 

ifneq ($(wildcard $(DEV_SNORT_INCLUDE)/framework/snort_api.h),)
	ISNORT := $(DEV_SNORT_INCLUDE)
else
	ISNORT := $(SYSTEM_SNORT_INCLUDE)
endif


.PHONY: build clean format gdb release release-test release test-data release-test-data local-test release-local-test usage

usage:
	@echo "Trout Snort plugins makefile instructions"
	@echo ""
	@echo "make build        - To build a debug build"
	@echo "make clean        - To clean all build folders"
	@echo "make deb-package  - Build Debian package with all components"
	@echo "make format       - To run clang-format on all source files"
	@echo "make gdb          - Launces gdb with local test files from the"
	@echo "                  - module defined by env TEST_MODULE"
	@echo "                    the test-local.script from the test folder"
	@echo "                    should be run from on a debug build"
	@echo "make live           Runs Snort with test_config/live.lua"
	@echo "make package      - Creates zip file with all components"
	@echo "make release      - To build a release build"
	@echo "make release-test - Run the test suite on release build"
	@echo "make release-test-data"
	@echo "                  - Run snort with test_config/cfg.lua on pcaps"
	@echo "                    in test_data on a release build"
	@echo "make release-test-local"
	@echo "                  - Set env TEST_MODULE to name of module where"
	@echo "                    the test-local.script from the test folder"
	@echo "                    should be run from on a release build"
	@echo "ubuntu-dev-deps   - Installs development packages needed for dev builds"
	@echo "ubuntu-run-deps   - Installs packages needed run time"
	@echo "make test         - Run the test suite"
	@echo "make test-break   - Run the test suite and break on first error"
	@echo "make test-data    - Run snort with test_config/cfg.lua on pcaps"
	@echo "                    in test_data"
	@echo "make test-local   - Set env TEST_MODULE to name of module where"
	@echo "                    the test-local.script from the test folder"
	@echo "                    should be run from on a debug build"
	@echo ""
	@echo "Debug builds will be written to:"
	@echo $(DEBUG_MODULE)
	@echo ""
	@echo "Release builds will be written to:"
	@echo $(RELEASE_MODULE)
	@echo ""
	@echo "It is recommended to add -jX to the make command, where X denotes"
	@echo "the number of threads that should be used for building, e.g."
	@echo "'make -j8 build' means use up to 8 threads when building."


test: $(DEBUG_MODULE) 
	@echo Testing "$(TEST_DIRS)"
	cd sh3;go install .
	sh3 -sanitize none -t $(DEBUG_MODULE) -tpath "$(TEST_DIRS)" $(TEST_LIMIT)

test-break: $(DEBUG_MODULE) 
	@echo Testing "$(TEST_DIRS)"
	cd sh3;go install .
	sh3 -sanitize none -break-on-error -t $(DEBUG_MODULE) -tpath "$(TEST_DIRS)" $(TEST_LIMIT)

release-test: $(RELEASE_MODULE)
	@echo Testing "$(TEST_DIRS)"
	cd sh3;go install
	sh3 -sanitize none -t $(RELEASE_MODULE) -tpath "$(TEST_DIRS)" $(TEST_LIMIT)

#############################################

define README_CONTENT
  !!!Do NOT store any content you want to keep in this folder!!!

  The folder is automatically generated by the build process and all
  content in it will be deleted at random.
endef

MAKE_README_FILENAME := $(MAKEDIR)/README.TXT

clean:
	if [ -f $(DEBUG_MODULE) ]; then rm $(DEBUG_MODULE); fi
	if [ -f $(RELEASE_MODULE) ]; then rm $(RELEASE_MODULE); fi
	if [ -d $(MAKEDIR) ]; then rm -r $(MAKEDIR); fi
	@echo "\e[3;32mClean done\e[0m"

release: $(RELEASE_MODULE) | $(RELEASEDIR)
	@echo Result output to:  $(RELEASE_MODULE)
	@echo Release build done!

build: $(DEBUG_MODULE) | $(DEBUGDIR)
	@echo Result output to:  $(DEBUG_MODULE)
	@echo Debug build done!

gdb: $(DEBUG_MODULE)
	@echo "\e[3;37mStarting debugger...\e[0m"
	gdb --args $(SNORT) -v -c plugins/$(TEST_MODULE)/tests/test-local.lua --plugin-path $(DEBUGDIR) $(SNORT_DAQ_INCLUDE_OPTION) --pcap-dir plugins/$(TEST_MODULE)/tests/pcaps --warn-all

format:
	clang-format -i $(CC_SOURCES) $(CC_HEADERS)

live: $(DEBUG_MODULE)
	$(SNORT) -v -c test_config/live.lua --plugin-path $(DEBUGDIR) $(SNORT_DAQ_INCLUDE_OPTION) --warn-all

test-data: $(DEBUG_MODULE)
	$(SNORT) -v -c test_config/cfg.lua --plugin-path $(DEBUGDIR) $(SNORT_DAQ_INCLUDE_OPTION) --pcap-dir test_data --warn-all

release-test-data: $(RELEASE_MODULE)
	$(SNORT) -v -c test_config/cfg.lua --plugin-path $(RELEASEDIR) $(SNORT_DAQ_INCLUDE_OPTION) --pcap-dir test_data --warn-all

# Look into using % in target (e.g. %/test-local)
# TODO: Update so it takes the test folder from the module definition, instead of having it hardcoded to 'tests'
test-local: $(DEBUG_MODULE)
	$(SNORT) -v -c plugins/$(TEST_MODULE)/tests/test-local.lua $(SNORT_DAQ_INCLUDE_OPTION) --plugin-path $(DEBUGDIR) --pcap-dir plugins/$(TEST_MODULE)/tests/pcaps --warn-all

release-test-local: $(RELEASE_MODULE)
	$(SNORT) -v -c plugins/$(TEST_MODULE)/tests/test-local.lua $(SNORT_DAQ_INCLUDE_OPTION) --plugin-path $(RELEASEDIR) --pcap-dir plugins/$(TEST_MODULE)/tests/pcaps --warn-all

$(MAKE_README_FILENAME): | $(MAKEDIR)
	$(file >$(MAKE_README_FILENAME),$(README_CONTENT))

$(MAKEDIR):
	mkdir -p $(MAKEDIR)

$(RELEASEDIR):
	mkdir -p $(RELEASEDIR)

$(DEBUGDIR):
	mkdir -p $(DEBUGDIR)

CC_SOURCES :=
CC_HEADERS :=
OBJS :=
DEPS :=
TEST_DIRS :=
LINK_DEPS :=
INC_DIRS :=
MODULE_LIST := 

########################################################################
# Reads FILES from all lib_def.mk files from all subfolders and adds 
# them with correct path to CC_SOURCES
define EXPAND_SOURCEFILES
  $(eval $(file <$(1)))
  LINK_DEPS += $(1)
  SRC_DIR := $(dir $(1))

  ifdef MODULE_NAME
    MODULE_LIST := $(MODULE_LIST) $(MODULE_NAME)
    undefine MODULE_NAME
  endif
  
  ifdef CC_FILES
    CC_SOURCES += $(addprefix $$(SRC_DIR),$(CC_FILES))
    undefine CC_FILES
  endif
  
  ifdef H_FILES
    CC_HEADERS += $(addprefix $$(SRC_DIR),$(H_FILES))
    undefine H_FILES
  endif
 
  ifdef TEST_FOLDER
    # TODO: Somehow make it so the test_folder can be retrieved from the module name, and use it for local-test and gdb targets
    TEST_DIRS := $(TEST_DIRS)$(addprefix $$(SRC_DIR),$(TEST_FOLDER));
    undefine TEST_FOLDER
  endif

  ifdef PUBLIC_INC
    INC_DIRS := $(INC_DIRS) -I $(addprefix $$(SRC_DIR),$(PUBLIC_INC))
    undefine PUBLIC_INC
  endif

  ifdef LOCAL_MAKEFILE
    include $(addprefix $$(SRC_DIR),$(LOCAL_MAKEFILE))
    undefine LOCAL_MAKEFILE    
  endif
  
endef

LIBDEFS = $(shell find $(SOURCEDIR) -name 'lib_def.mk')
$(foreach mk_file,$(LIBDEFS),$(eval $(call EXPAND_SOURCEFILES,$(mk_file))))
########################################################################

OBJS=$(abspath $(addprefix $(MAKEDIR)/, $(subst .cc,.o,$(CC_SOURCES))))
DEPS=$(abspath $(addprefix $(MAKEDIR)/, $(subst .cc,.d,$(CC_SOURCES))))

# Include dependencies if they exists
-include ${DEPS}

# Rule for how to compile .cc files to .o files
$(MAKEDIR)/%.o : %.cc | $(MAKE_README_FILENAME)
	@mkdir -p $(dir $@)
	g++ -MMD -MT '$(patsubst %.cc,$(MAKEDIR)/%.o,$<)' -pipe -O0 -std=c++2b -Wall -fPIC -Wextra -g -I $(ISNORT) $(INC_DIRS) -c $< -o $@

# Rule for linking debug build (how to generate $(OUTPUTDIR)/$(DEBUG_MODULE) )
$(DEBUG_MODULE): $(OBJS) $(LINK_DEPS) | $(DEBUGDIR)
	@echo "\e[3;37mLinking...\e[0m"
	g++ $(OBJS) -shared -O0 -Wall -g -Wextra -o $(DEBUG_MODULE)

# Rule for linking release build (how to generate $(OUTPUTDIR)/$(RELEASE_MODULE) )
$(RELEASE_MODULE): $(CC_SOURCES) $(LINK_DEPS) | $(RELEASEDIR)
	@echo "\e[3;37mLinking...\e[0m"
	g++ -O3 -std=c++2b -fPIC -Wall -Wextra -shared -I $(ISNORT) $(INC_DIRS) $(CC_SOURCES) -o $(RELEASE_MODULE)	


##### SNORT BUILDING STUFF #####

$(DEPS_FOLDER):
	mkdir -p $(DEPS_FOLDER)

$(SNORT3_FILE): | $(DEPS_FOLDER)
	curl -q -L https://github.com/snort3/snort3/archive/refs/tags/$(SNORT3_TAG).tar.gz -o $(SNORT3_FILE)

$(LIBML_FILE): | $(DEPS_FOLDER)
	curl -q -L https://github.com/snort3/libml/archive/refs/tags/$(LIBML_TAG).tar.gz -o $(LIBML_FILE)

$(LIBDAQ_FILE): | $(DEPS_FOLDER)
	curl -q -L https://github.com/snort3/libdaq/archive/refs/tags/$(LIBDAQ_TAG).tar.gz -o $(LIBDAQ_FILE)

$(SNORT3_FOLDER): $(SNORT3_FILE) | $(DEPS_FOLDER)
	bsdtar -xf $< -C $(DEPS_FOLDER)

$(LIBML_FOLDER): $(LIBML_FILE) | $(DEPS_FOLDER)
	bsdtar -xf $< -C $(DEPS_FOLDER)

$(LIBDAQ_FOLDER): $(LIBDAQ_FILE) | $(DEPS_FOLDER)
	bsdtar -xf $< -C $(DEPS_FOLDER)

.PHONY: libdaq libml snort3

$(LIBDAQ_INSTALL_FOLDER): $(LIBDAQ_FOLDER)
	cd $(LIBDAQ_FOLDER); ./bootstrap
	cd $(LIBDAQ_FOLDER); ./configure --prefix=$(LIBDAQ_INSTALL_FOLDER)
	cd $(LIBDAQ_FOLDER); $(MAKE)
	cd $(LIBDAQ_FOLDER); $(MAKE) install

libdaq: $(LIBDAQ_INSTALL_FOLDER)

$(LIBML_INSTALL_FOLDER): $(LIBML_FOLDER)
	cd $(LIBML_FOLDER); ./configure.sh --prefix=$(LIBML_INSTALL_FOLDER)
	cd $(LIBML_FOLDER)/build; $(MAKE) install/strip

libml: $(LIBML_INSTALL_FOLDER) 

$(SNORT3_INSTALL_FOLDER): $(SNORT3_FOLDER) $(LIBDAQ_INSTALL_FOLDER) $(LIBML_INSTALL_FOLDER)
	cd $(SNORT3_FOLDER); ./configure_cmake.sh --with-daq-includes=$(LIBDAQ_INSTALL_FOLDER)/include --with-daq-libraries=$(LIBDAQ_INSTALL_FOLDER)/lib --with-libml-includes=$(LIBML_INSTALL_FOLDER)/include --with-libml-libraries=$(LIBML_INSTALL_FOLDER)/lib --prefix=$(SNORT3_INSTALL_FOLDER)
	cd $(SNORT3_FOLDER)/build; $(MAKE) install

snort3: $(SNORT3_INSTALL_FOLDER)

.PHONY: ubuntu-dev-deps ubuntu-run-deps snort3/clean snort3/build snort3/dev package

ubuntu-dev-deps:
	# The irony of having make in this list isn't unnoticed
	sudo apt install $(UBUNTU_DEV_TIME_DEPS)

ubuntu-run-deps:
	sudo apt install $(UBUNTU_RUN_TIME_DEPS)

snort3/clean:
	if [ -d $(LIBDAQ_FOLDER) ]; then rm -r $(LIBDAQ_FOLDER); fi
	if [ -d $(LIBDAQ_INSTALL_FOLDER) ]; then rm -r $(LIBDAQ_INSTALL_FOLDER); fi
	if [ -d $(LIBML_FOLDER) ]; then rm -r $(LIBML_FOLDER); fi
	if [ -d $(LIBML_INSTALL_FOLDER) ]; then rm -r $(LIBML_INSTALL_FOLDER); fi
	if [ -d $(SNORT3_FOLDER) ]; then rm -r $(SNORT3_FOLDER); fi
	if [ -d $(SNORT3_INSTALL_FOLDER) ]; then rm -r $(SNORT3_INSTALL_FOLDER); fi
	@echo "\e[3;32mDependency clean done\e[0m"

snort3/build: snort3 

snort3/dev: snort3 
	if [ -d $(DEV_FOLDER) ]; then rm -rf $(DEV_FOLDER) ; fi
	@mkdir -p $(DEV_FOLDER)/include/snort
	@cp -r $(LIBDAQ_INSTALL_FOLDER)/include/. $(DEV_FOLDER)/include/snort/
	@cp -r $(LIBDAQ_INSTALL_FOLDER)/bin/. $(DEV_FOLDER)/bin/
	@cp -r $(LIBDAQ_INSTALL_FOLDER)/lib/. $(DEV_FOLDER)/lib/
	@cp -r $(LIBML_INSTALL_FOLDER)/include/. $(DEV_FOLDER)/include/snort/
	@cp -r $(LIBML_INSTALL_FOLDER)/lib/. $(DEV_FOLDER)/lib/
	@cp -r $(SNORT3_INSTALL_FOLDER)/. $(DEV_FOLDER)
	@echo "Snort files written to $(DEV_FOLDER)" 
	@echo "\e[3;32mSnort3 build\e[0m"

package: snort3/dev build
	@cp -r $(DEBUG_MODULE) $(DEV_FOLDER)/bin/
	@echo Copying done - building package...
	tar -cf snort.tar -C $(DEV_FOLDER) bin
	tar -rf snort.tar -C $(DEV_FOLDER) etc
	tar -rf snort.tar -C $(DEV_FOLDER) lib
	tar -rf snort.tar -C $(DEV_FOLDER) share
	tar -rf snort.tar scripts
	@if [ -f snort.tar.gz ]; then rm snort.tar.gz; fi
	gzip snort.tar
	@echo "Package building done (./snort.tar.gz)..."

include makefile_nfpm

deb-package: snort3 release | $(MAKE_README_FILENAME)
	@echo Generating package script...
	$(file > $(MAKEDIR)/nfpm.yaml,$(nfpm_script))
	@echo "\e[3;32mPackage script generated: $(MAKEDIR)/nfpm.yaml\e[0m"
	@echo Building deb package....
	nfpm p -f $(MAKEDIR)/nfpm.yaml -p deb -t .

