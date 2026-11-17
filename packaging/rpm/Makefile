PACKAGE_NAME?=	x2kafka

VERSION?=	$(shell cat ../../VERSION 2>/dev/null || git describe --abbrev=6 --tags HEAD --always 2>/dev/null | sed 's/-/_/g' || echo "1.0.0")

BUILD_NUMBER?= 1

MOCK_CONFIG?=default

RESULT_DIR?=pkgs

# NDPI=1 builds x2kafka with nDPI (sFlow application classification): the
# release tarball is downloaded and the spec (--with ndpi) links it statically.
NDPI?=		0
NDPI_VERSION?=	6.0
NDPI_TARBALL=	SOURCES/nDPI-$(NDPI_VERSION).tar.gz
NDPI_URL?=	https://github.com/ntop/nDPI/archive/refs/tags/$(NDPI_VERSION).tar.gz

all: rpm

SOURCES:
	mkdir -p SOURCES

archive: SOURCES
	cd ../../ && \
	tar --exclude-vcs \
		--exclude='./packaging/rpm/SOURCES' \
		--exclude='./packaging/rpm/pkgs' \
		--transform 's/^\./$(PACKAGE_NAME)-$(VERSION)/' \
		-czf packaging/rpm/SOURCES/$(PACKAGE_NAME)-$(VERSION).tar.gz .

ndpi: $(NDPI_TARBALL)

$(NDPI_TARBALL): | SOURCES
	curl -fsSL -o $@.tmp $(NDPI_URL)
	mv $@.tmp $@

ifeq ($(NDPI),1)
MOCK_NDPI_OPTS=	--with ndpi --define "ndpi_version $(NDPI_VERSION)"
PREPARE_DEPS=	archive ndpi
else
MOCK_NDPI_OPTS=
PREPARE_DEPS=	archive
endif

build_prepare: $(PREPARE_DEPS)
	mkdir -p $(RESULT_DIR)
	rm -f $(RESULT_DIR)/$(PACKAGE_NAME)*.rpm $(RESULT_DIR)/kafka2x*.rpm

srpm: build_prepare
	/usr/bin/mock \
		-r $(MOCK_CONFIG) \
		--define "__version $(VERSION)" \
		--define "__release $(BUILD_NUMBER)" \
		$(MOCK_NDPI_OPTS) \
		--resultdir=$(RESULT_DIR) \
		--buildsrpm \
		--spec=x2kafka.spec \
		--sources=SOURCES
	@echo "======= Source RPM now available in $(RESULT_DIR) ======="

rpm: srpm
	/usr/bin/mock \
		-r $(MOCK_CONFIG) \
		--define "__version $(VERSION)"\
		--define "__release $(BUILD_NUMBER)"\
		$(MOCK_NDPI_OPTS) \
		--resultdir=$(RESULT_DIR) \
		--rebuild $(RESULT_DIR)/$(PACKAGE_NAME)*.src.rpm
	@echo "======= Binary RPMs now available in $(RESULT_DIR) ======="

clean:
	rm -rf SOURCES pkgs

distclean: clean
	rm -f build.log root.log state.log available_pkgs installed_pkgs \
		*.rpm *.tar.gz
