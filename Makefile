FRIDA_VERSION := 17.3.0
YOUTUBE_IPA := ./ipa/YouTube_4.51.08_decrypted.ipa
MUTUBE_HOOKS := ./bin/MuTubeHooks.dylib
GUM_GRAFT := ./bin/gum-graft-$(FRIDA_VERSION)-macos-arm64

# tvOS SDK settings
TVOS_SDK := appletvos
TVOS_MIN_VERSION := 13.0

.PHONY: all
all: mutube.ipa

$(GUM_GRAFT):
	@echo "Downloading gum-graft..."
	mkdir -p ./bin
	wget https://github.com/frida/frida/releases/download/$(FRIDA_VERSION)/gum-graft-$(FRIDA_VERSION)-macos-arm64.xz -P ./bin
	unxz -k ./bin/gum-graft-$(FRIDA_VERSION)-macos-arm64.xz
	chmod +x ./bin/gum-graft-$(FRIDA_VERSION)-macos-arm64

$(MUTUBE_HOOKS): MuTubeHooks.mm
	@echo "Building MuTubeHooks.dylib..."
	mkdir -p ./bin
	xcrun -sdk $(TVOS_SDK) clang++ \
		-arch arm64 \
		-dynamiclib \
		-o $(MUTUBE_HOOKS) \
		-mtvos-version-min=$(TVOS_MIN_VERSION) \
		-framework Foundation \
		-fobjc-arc \
		-O2 \
		MuTubeHooks.mm

mutube.ipa: $(YOUTUBE_IPA) $(MUTUBE_HOOKS) $(GUM_GRAFT)
	$(eval TMPDIR := $(shell mktemp -d ./.make-tmp_XXXXXXXX))

	mkdir -p $(TMPDIR)/yt-unzip
	unzip -q $(YOUTUBE_IPA) -d $(TMPDIR)/yt-unzip
	cp $(MUTUBE_HOOKS) $(TMPDIR)/yt-unzip/Payload/YouTubeUnstable.app/Frameworks/MuTubeHooks.dylib
	# Use gum-graft to instrument the binary (replaces Frida Gadget)
	$(GUM_GRAFT) $(TMPDIR)/yt-unzip/Payload/YouTubeUnstable.app/YouTubeUnstable --instrument=0xed5270 --instrument=0x152d508
	insert_dylib --strip-codesig --inplace '@executable_path/Frameworks/MuTubeHooks.dylib' $(TMPDIR)/yt-unzip/Payload/YouTubeUnstable.app/YouTubeUnstable
	cd $(TMPDIR)/yt-unzip && zip -qr injected.ipa Payload
	mv $(TMPDIR)/yt-unzip/injected.ipa mutube.ipa

	rm -rf $(TMPDIR)

.PHONY: clean
clean:
	rm -rf ./.make-tmp_* mutube.ipa
