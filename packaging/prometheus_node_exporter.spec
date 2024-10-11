%define _tmpdir /tmp/node_exporter
%define NODE_EXPORTER_VERSION 1.8.2_cloudify_rebuild
%define _url https://repository.cloudifysource.org/cloudify/components/node_exporter-%{NODE_EXPORTER_VERSION}.linux-%{arch}.tar.gz

Name:           node_exporter
Version:        %{NODE_EXPORTER_VERSION}
Release:        1%{?dist}
Summary:        Prometheus node_exporter
Group:          Applications/Multimedia
License:        Apache 2.0
URL:            https://github.com/prometheus/node_exporter
Packager:       Cloudify Platform Ltd.

BuildRequires:  curl

%description
Prometheus node_exporter.

%build
mkdir -p %{_tmpdir}
curl -L -o %{_tmpdir}/node_exporter.tar.gz %{_url}
tar -xvf %{_tmpdir}/node_exporter.tar.gz -C %{_tmpdir} --strip=1

%install
mkdir -p %{buildroot}/usr/local/bin/
install -m 755 %{_tmpdir}/node_exporter %{buildroot}/usr/local/bin
rm -rf %{_tmpdir}

%files
%attr(755,root,wheel)/usr/local/bin/node_exporter
