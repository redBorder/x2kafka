Version: %{__version}
Release: %{__release}%{?dist}
Name: x2kafka
License: GNU AGPLv3
URL: https://github.com/redBorder/x2kafka
Source0: %{name}-%{version}.tar.gz
# Optional nDPI support (sFlow application classification), off by default.
# Enable with `rpmbuild --with ndpi` / `mock --with ndpi` (make rpm NDPI=1):
# nDPI is then built as a static library and linked into x2kafka.
%bcond_with ndpi
%if %{with ndpi}
%{!?ndpi_version: %define ndpi_version 6.0}
Source1: nDPI-%{ndpi_version}.tar.gz
%endif

BuildRequires: golang
%if %{with ndpi}
BuildRequires: gcc, make, autoconf, automake, libtool, pkgconfig, which
%endif

Summary: Convert data events from Unix sockets, FIFOs, Syslog or HTTP to Kafka
Group: Development/Libraries/C and C++
Requires(pre): shadow-utils

%description
%{summary}

%package -n kafka2x
Summary: Forward data events from Kafka topics to HTTP/REST endpoints
Group: Development/Libraries/C and C++
Requires(pre): shadow-utils

%description -n kafka2x
Forward data events from Kafka topics to HTTP/REST endpoints with batching and compression.

%prep
%setup -qn %{name}-%{version}
%if %{with ndpi}
mkdir -p _ndpi_build
tar -xzf %{SOURCE1} -C _ndpi_build --strip-components=1
%endif

%build
go build -ldflags "-X main.version=%{version} -X main.revision=%{release}" -o kafka2x ./cmd/kafka2x

%if %{with ndpi}
%define ndpi_prefix %{_builddir}/%{name}-%{version}/_ndpi_inst
cd _ndpi_build
./autogen.sh
./configure --prefix=%{ndpi_prefix} --enable-static --disable-shared --with-only-libndpi
make %{?_smp_mflags}
make install
cd ..
# Make sure only the static libndpi.a can be picked up by the linker
rm -f %{ndpi_prefix}/lib/*.so* %{ndpi_prefix}/lib64/*.so*

export CGO_ENABLED=1
export CGO_CFLAGS="-I%{ndpi_prefix}/include"
export CGO_LDFLAGS="-L%{ndpi_prefix}/lib -L%{ndpi_prefix}/lib64 -lndpi -lm -lpthread"
go build -tags ndpi -ldflags "-X main.version=%{version} -X main.revision=%{release}" -o x2kafka ./cmd/x2kafka
%else
go build -ldflags "-X main.version=%{version} -X main.revision=%{release}" -o x2kafka ./cmd/x2kafka
%endif

%install
mkdir -p %{buildroot}/usr/bin
install -p -m 755 x2kafka %{buildroot}/usr/bin/x2kafka
install -p -m 755 kafka2x %{buildroot}/usr/bin/kafka2x
mkdir -p %{buildroot}/etc/x2kafka
mkdir -p %{buildroot}/etc/kafka2x
install -D -m 644 resources/systemd/x2kafka.service %{buildroot}/usr/lib/systemd/system/x2kafka.service
install -D -m 644 resources/systemd/kafka2x.service %{buildroot}/usr/lib/systemd/system/kafka2x.service
install -D -m 644 configs_example/x2kafka_config.json %{buildroot}/etc/x2kafka/config.json
install -D -m 644 configs_example/kafka2x_config.json %{buildroot}/etc/kafka2x/config.json

%clean
rm -rf %{buildroot}

%pre
getent group x2kafka >/dev/null || groupadd -r x2kafka
getent passwd x2kafka >/dev/null || \
    useradd -r -g x2kafka -d / -s /sbin/nologin \
    -c "User of x2kafka service" x2kafka
exit 0

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%pre -n kafka2x
getent group kafka2x >/dev/null || groupadd -r kafka2x
getent passwd kafka2x >/dev/null || \
    useradd -r -g kafka2x -d / -s /sbin/nologin \
    -c "User of kafka2x service" kafka2x
exit 0

%post -n kafka2x -p /sbin/ldconfig
%postun -n kafka2x -p /sbin/ldconfig

%files
%defattr(755,root,root,755)
/usr/bin/x2kafka
%defattr(644,root,root,755)
%dir /etc/x2kafka
%config(noreplace) /etc/x2kafka/config.json
/usr/lib/systemd/system/x2kafka.service

%files -n kafka2x
%defattr(755,root,root,755)
/usr/bin/kafka2x
%defattr(644,root,root,755)
%dir /etc/kafka2x
%config(noreplace) /etc/kafka2x/config.json
/usr/lib/systemd/system/kafka2x.service

%changelog
* Sat Sep 26 2026 David Vanhoucke <dvanhoucke@redborder.com> - 1.0.0-1
- Initial release of x2kafka and kafka2x Go daemons
