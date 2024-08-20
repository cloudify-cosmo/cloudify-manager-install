%define _tmpdir /tmp/prometheus
%define PROMETHEUS_VERSION 2.53.2
%define _url https://github.com/prometheus/prometheus/releases/download/v%{PROMETHEUS_VERSION}/prometheus-%{PROMETHEUS_VERSION}.linux-%{arch}.tar.gz

# Prevent mangling shebangs (RH8 build default), which fails
#  with the test files of networkx<2 due to RH8 not having python2.
%if "%{dist}" != ".el7"
%undefine __brp_mangle_shebangs
# Prevent creation of the build ids in /usr/lib, so we can still keep our RPM
#  separate from the official RH supplied software (due to a change in RH8)
%define _build_id_links none
%endif

Name:           prometheus
Version:        %{PROMETHEUS_VERSION}
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
mkdir -p %{buildroot}/var/log/cloudify/prometheus

%pre
groupadd -fr cfylogs
groupadd -fr cfyuser
getent passwd cfyuser >/dev/null || useradd -r -g cfyuser -d /etc/cloudify -s /sbin/nologin cfyuser

%files
%attr(755,root,wheel)/usr/local/bin/prometheus
%attr(755,root,wheel)/usr/local/bin/promtool
%attr(755,root,wheel)/etc/prometheus/consoles/
%attr(755,root,wheel)/etc/prometheus/console_libraries/
%attr(750,cfyuser,cfylogs) /var/log/cloudify/prometheus
