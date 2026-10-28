include $(THEOS)/makefiles/common.mk

TOOL_NAME = contrainstalld
contrainstalld_FILES = $(wildcard Common/*.swift Common/*.c Common/*.m Installer/*.swift Zip/*.c Zip/*.swift) main.m 
contrainstalld_INSTALL_PATH = /usr/libexec
contrainstalld_FRAMEWORKS = Foundation Security CoreFoundation CryptoKit
contrainstalld_LIBRARIES = sqlite3
contrainstalld_CFLAGS = -I. -Iinclude -I$(THEOS_PROJECT_DIR)/Shared
contrainstalld_CODESIGN_FLAGS = -Scontrainstalld.entitlements
contrainstalld_SWIFT_BRIDGING_HEADER = include/contrainstalld-Bridging-Header.h


include $(THEOS_MAKE_PATH)/tool.mk
