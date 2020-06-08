%define _tmpdir /tmp/rabbitmq_exporter
%define _url    https://github.com/kbudde/rabbitmq_exporter/releases/download/v1.0.0-RC7/rabbitmq_exporter-1.0.0-RC7.linux-amd64.tar.gz
Name:           rabbitmq_exporter
Version:        1.0.0
Release:        RC7%{?dist}
Summary:        Prometheus rabbitmq_exporter
Group:          Applications/Multimedia
License:        MIT
URL:            https://github.com/prometheus/rabbitmq_exporter
Packager:       Cloudify Platform Ltd.

BuildRequires:  curl

%description
Prometheus rabbitmq_exporter.

%build
mkdir -p %{_tmpdir}
curl -L -o %{_tmpdir}/rabbitmq_exporter.tar.gz %{_url}
tar -xvf %{_tmpdir}/rabbitmq_exporter.tar.gz -C %{_tmpdir} --strip=1

%install
mkdir -p %{buildroot}/usr/local/bin/
install -m 755 %{_tmpdir}/rabbitmq_exporter %{buildroot}/usr/local/bin
rm -rf %{_tmpdir}

%files
%attr(755,root,wheel)/usr/local/bin/rabbitmq_exporter
