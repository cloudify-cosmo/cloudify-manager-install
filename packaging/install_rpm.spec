%define _venv /opt/cloudify/cfy_manager
%define __python %_venv/bin/python
%define __find_provides %{nil}
%define __find_requires %{nil}
%define _use_internal_dependency_generator 0

%define _source_payload w0.gzdio
%define _binary_payload w0.gzdio

# Prevent mangling shebangs (RH8 build default), which fails
#  with the test files of networkx<2 due to RH8 not having python2.
%if "%{dist}" != ".el7"
%undefine __brp_mangle_shebangs
# Prevent creation of the build ids in /usr/lib, so we can still keep our RPM
#  separate from the official RH supplied software (due to a change in RH8)
%define _build_id_links none
%endif

Name:           cloudify-manager-install
Version:        %{CLOUDIFY_VERSION}
Release:        %{CLOUDIFY_PACKAGE_RELEASE}%{?dist}
Summary:        Cloudify Manager installer
Group:          Applications/Multimedia
License:        Apache 2.0
URL:            https://github.com/cloudify-cosmo/cloudify-manager-install
Vendor:         Cloudify Platform Ltd.
Packager:       Cloudify Platform Ltd.

BuildRequires:  createrepo, gcc, postgresql-devel
Requires(pre):  shadow-utils
Requires:       python3 >= 3.6

Source0:        https://cloudify-cicd.s3.amazonaws.com/python-build-packages/cfy-python3.11-%{ARCHITECTURE}.tgz

%description
Cloudify Manager installer.

%prep
sudo tar xf %{S:0} -C /

%build

# Create the venv with the custom Python symlinked in
mkdir -p $(dirname %_venv)
/opt/python3.11/bin/python3.11 -m venv %_venv
%_venv/bin/pip install setuptools --upgrade
%_venv/bin/pip install ${RPM_SOURCE_DIR}
# Make sure the http.py spurious critical log is in the expected location (line 849)
# We're doing this because the socket is already secured by filesystem permissions and
# we don't want a meaningless log entry with a CRIT level to alarm users
sed -n 849p %_venv/lib/python3.11/site-packages/supervisor/http.py | grep critical
sed -i 849s/critical/debug/ %_venv/lib/python3.11/site-packages/supervisor/http.py

%install

# Copy our custom Python to build root
mkdir -p %{buildroot}/opt/python3.11
cp -R /opt/python3.11 %{buildroot}/opt

mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/cloudify
mkdir -p %{buildroot}/opt/cloudify
mkdir -p %{buildroot}/run/cloudify
mkdir -p %{buildroot}/etc/supervisord.d
cp ${RPM_SOURCE_DIR}/config.yaml %{buildroot}/etc/cloudify/config.yaml
cp ${RPM_SOURCE_DIR}/rpms %{buildroot}/opt/cloudify/sources -Lfr
cp -R ${RPM_SOURCE_DIR}/packaging/files/* %{buildroot}

mv %_venv %{buildroot}%_venv
ln -s %_venv/bin/cfy_manager %{buildroot}/usr/bin/cfy_manager
ln -s %_venv/bin/supervisorctl %{buildroot}/usr/bin/supervisorctl
ln -s %_venv/bin/supervisord %{buildroot}/usr/bin/supervisord

/bin/createrepo %{buildroot}/opt/cloudify/sources
mkdir -p %{buildroot}/etc/yum.repos.d/
cp ${RPM_SOURCE_DIR}/packaging/localrepo %{buildroot}/etc/yum.repos.d/Cloudify-Local.repo
mkdir -p %{buildroot}/var/log/cloudify

curl https://cloudify-release-eu.s3.amazonaws.com/cloudify/%{CLOUDIFY_VERSION}/%{CLOUDIFY_PACKAGE_RELEASE}-release/metadata.json -o %{buildroot}/etc/cloudify/metadata.json

%pre
ver=`cat /etc/redhat-release | grep -o 'release.*' | cut -f2 -d\ | cut -b 1-3`
min_ver=7.6
if (( $(awk 'BEGIN {print ("'$ver'"<"'$min_ver'")}') )); then
    >&2 echo "[ERROR] OS version earlier than $min_ver, exiting."
    exit 1;
fi

groupadd -fr cfylogs
groupadd -fr cfyuser
getent passwd cfyuser >/dev/null || useradd -r -g cfyuser -d /etc/cloudify -s /sbin/nologin cfyuser
groupadd -fr rabbitmq
getent passwd rabbitmq >/dev/null || useradd -r -g rabbitmq -d /var/lib/rabbitmq -s /sbin/nologin rabbitmq
usermod -aG rabbitmq cfyuser
usermod -aG cfyuser rabbitmq
groupadd -fr nginx
getent passwd nginx >/dev/null || useradd -r -g nginx -d /var/cache/nginx -s /sbin/nologin nginx
usermod -aG cfylogs nginx

%post
echo "
###########################################################################
Cloudify installer is ready!
To install Cloudify Manager, run:
cfy_manager install --private-ip <PRIVATE_IP> --public-ip <PUBLIC_IP>
(Use cfy_manager -h for a full list of options)

You can specify more installation settings in /etc/cloudify/config.yaml. If you
specify the public and private IP addresses in the config.yaml file, run:
cfy_manager install
###########################################################################
"

%files
%attr(0755,cfyuser,cfyuser)     /opt/python3.11

/usr/bin/cfy_manager
/opt/cloudify
/etc/supervisord.d
%attr(755,cfyuser,cfyuser) /etc/cloudify
%attr(660,root,wheel) %config(noreplace) /etc/cloudify/config.yaml
/etc/yum.repos.d/Cloudify-Local.repo
/usr/lib/systemd/system/supervisord.service
/etc/supervisord.conf
/etc/rsyslog.d/39-cloudify-perms.conf
/etc/rsyslog.d/50-supervisord.conf
/etc/rsyslog.d/51-cloudify-perms.conf
/usr/bin/supervisorctl
/usr/bin/supervisord
%attr(751,cfyuser,cfylogs) /var/log/cloudify
%attr(750,cfyuser,cfyuser) /run/cloudify
