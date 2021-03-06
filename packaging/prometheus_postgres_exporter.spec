%define _tmpdir /tmp/postgres_exporter
%define _url    https://github.com/wrouesnel/postgres_exporter/releases/download/v0.8.0/postgres_exporter_v0.8.0_linux-amd64.tar.gz
Name:           postgres_exporter
Version:        0.8.0
Release:        1%{?dist}
Summary:        Prometheus postgres_exporter
Group:          Applications/Multimedia
License:        Apache 2.0
URL:            https://github.com/prometheus/postgres_exporter
Packager:       Cloudify Platform Ltd.

BuildRequires:  curl

%description
Prometheus postgres_exporter.

%build
mkdir -p %{_tmpdir}
curl -L -o %{_tmpdir}/postgres_exporter.tar.gz %{_url}
tar -xvf %{_tmpdir}/postgres_exporter.tar.gz -C %{_tmpdir} --strip=1

%install
mkdir -p %{buildroot}/usr/local/bin/
install -m 755 %{_tmpdir}/postgres_exporter %{buildroot}/usr/local/bin
rm -rf %{_tmpdir}

%files
%attr(755,root,wheel)/usr/local/bin/postgres_exporter
