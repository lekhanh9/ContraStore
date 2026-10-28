THEOS_PROJECT_DIR ?= ..
include $(THEOS)/makefiles/common.mk

TOOL_NAME = ct

ct_FILES = main.m $(THEOS_PROJECT_DIR)/Shared/ContraXPCClient.m
ct_CFLAGS = -fobjc-arc -I$(THEOS_PROJECT_DIR)/Shared
ct_FRAMEWORKS = Foundation Security
ct_CODESIGN_FLAGS = -Sct.entitlements
ct_INSTALL_PATH = /usr/bin

include $(THEOS_MAKE_PATH)/tool.mk
