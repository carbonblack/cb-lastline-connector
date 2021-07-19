%define name python-cb-lastline-connector
%define version 2.0.0
%define release 1
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
%define _build_id_links none

%define venv_location $VIRTUAL_ENV_PATH

Summary: VMware Carbon Black EDR lastline Connector
Name: %{name}
Version: %{version}
Release: %{release}%{?dist}
Source0: %{name}-%{version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: VMware Carbon Black
Url: http://www.carbonblack.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{version}

%build
%{venv_location}/bin/pyinstaller cb-lastline-connector.spec

%install
%{venv_location}/bin/python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%posttrans
mkdir -p /usr/share/cb/integrations/lastline/db
chkconfig --add cb-lastline-connector
chkconfig --level 345 cb-lastline-connector on

# not auto-starting because conf needs to be updated
#/etc/init.d/cb-lastline-connector start


%preun
/etc/init.d/cb-lastline-connector stop

# only delete the chkconfig entry when we uninstall for the last time,
# not on upgrades
if [ "X$1" = "X0" ]
then
    chkconfig --del cb-lastline-connector
fi


%files -f INSTALLED_FILES
%defattr(-,root,root)
