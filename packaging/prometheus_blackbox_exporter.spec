%define _tmpdir /tmp/blackbox_exporter
%define _url    https://github.com/prometheus/blackbox_exporter/releases/download/v0.18.0/blackbox_exporter-0.18.0.linux-amd64.tar.gz
Name:           blackbox_exporter
Version:        0.18.0
Release:        1%{?dist}
Summary:        Prometheus blackbox_exporter
Group:          Applications/Multimedia
License:        Apache 2.0
URL:            https://github.com/prometheus/blackbox_exporter
Packager:       Cloudify Platform Ltd.

BuildRequires:  curl

%description
Prometheus blackbox_exporter.

%build
mkdir -p %{_tmpdir}
curl -L -o %{_tmpdir}/blackbox_exporter.tar.gz %{_url}
tar -xvf %{_tmpdir}/blackbox_exporter.tar.gz -C %{_tmpdir} --strip=1

%install
mkdir -p %{buildroot}/usr/local/bin/
install -m 755 %{_tmpdir}/blackbox_exporter %{buildroot}/usr/local/bin
rm -rf %{_tmpdir}

%files
%attr(755,root,wheel)/usr/local/bin/blackbox_exporter
