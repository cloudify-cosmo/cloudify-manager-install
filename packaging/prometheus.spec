%define _tmpdir /tmp/prometheus
%define _url    https://github.com/prometheus/prometheus/releases/download/v2.18.1/prometheus-2.18.1.linux-amd64.tar.gz
Name:           prometheus
Version:        2.18.1
Release:        1%{?dist}
Summary:        The Prometheus monitoring system and time series database.
Group:          Applications/Multimedia
License:        MIT
URL:            https://github.com/prometheus/prometheus
Packager:       Cloudify Platform Ltd.

BuildRequires:  curl

%description
The Prometheus monitoring system and time series database.

%build
mkdir -p %{_tmpdir}
curl -L -o %{_tmpdir}/prometheus.tar.gz %{_url}
tar -xvf %{_tmpdir}/prometheus.tar.gz -C %{_tmpdir} --strip=1

%install
mkdir -p %{buildroot}/usr/local/bin/
install -m 755 %{_tmpdir}/prometheus %{buildroot}/usr/local/bin
install -m 755 %{_tmpdir}/promtool %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/etc/prometheus
cp -a %{_tmpdir}/consoles %{buildroot}/etc/prometheus
cp -a %{_tmpdir}/console_libraries %{buildroot}/etc/prometheus
rm -rf %{_tmpdir}

%files
%attr(755,root,wheel)/usr/local/bin/prometheus
%attr(755,root,wheel)/usr/local/bin/promtool
%attr(755,root,wheel)/etc/prometheus/consoles/
%attr(755,root,wheel)/etc/prometheus/console_libraries/
