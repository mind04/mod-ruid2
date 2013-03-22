Summary: Run all httpd process under user's access right.
Name: mod_ruid2
Version: 0.9.8
Release: 1%{dist}
Group: System Environment/Daemons
URL: http://sourceforge.net/projects/mod-ruid/
Source0: http://sourceforge.net/projects/mod-ruid/files/mod_ruid2/mod_ruid2-%{version}.tar.bz2
License: Apache Software License version 2
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildRequires: httpd-devel >= 2.0.40 libcap-devel
Requires: httpd >= 2.0.40 libcap
Obsoletes: mod_ruid

%description
With this module, all httpd process run under user's access right, not nobody or apache.
mod_ruid2 is similar to mod_suid2, but has better performance than mod_suid2 because it
doesn`t need to kill httpd children after one request. It makes use of kernel capabilites
and after receiving a new request suids again. If you want to run apache modules, i.e.
WebDAV, PHP, and so on under user's right, this module is useful.

%prep
%setup -q

%build
%{_sbindir}/apxs -l cap -c %{name}.c
mv .libs/%{name}.so .
%{__strip} -g %{name}.so

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_libdir}/httpd/modules
install -m755 %{name}.so $RPM_BUILD_ROOT%{_libdir}/httpd/modules

# Install the config file
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d
install -m 644 ruid2.conf \
    $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/
    
%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%doc README LICENSE
%attr(755,root,root)%{_libdir}/httpd/modules/*.so
%config(noreplace) %{_sysconfdir}/httpd/conf.d/*.conf


%changelog
* Fri Mar 22 2013 Kees Monshouwer <km|monshouwer_com> 0.9.8-1
- Address reported security bug in chroot mode. Thanks to the
  "cPanel Security Team" for the discovery of this bug.
- Improve chroot behavior in drop capability mode.

* Wed Apr 11 2012 Kees Monshouwer <km|monshouwer_com> 0.9.7-1
- Update to 0.9.7
- Reduction of memory usage, especially in large deployments

* Wed Apr 11 2012 Kees Monshouwer <km|monshouwer_com> 0.9.6-1
- Update to 0.9.6
- Fixed: user group exchange in default config

* Wed Mar 07 2012 Kees Monshouwer <km|monshouwer_com> 0.9.5-1
- Update to 0.9.5
- Switch default mode to 'config' !!!
- Apache 2.4 compatibility

* Wed Feb 23 2011 Kees Monshouwer <km|monshouwer.com> 0.9.4-1
- Update to 0.9.4
- Fixed: mod_security incompatibility issue

* Tue Jan 04 2011 Kees Monshouwer <km|monshouwer_com> 0.9.3-1
- Update to 0.9.3
- Fixed: chroot issue with sub-requests caused by mod_rewrite 

* Tue Dec 20 2010 Kees Monshouwer <km|monshouwer_com> 0.9.2-1
- Update to 0.9.2
- Fixed: array subscript was above array bounds in ruid_set_perm

* Mon Oct 18 2010 Kees Monshouwer <km|monshouwer_com> 0.9.1-1
- Update to 0.9.1

* Wed Jun 23 2010 Kees Monshouwer <km|monshouwer_com> 0.9-1
- Added chroot functionality 
- Update to 0.9

* Mon Jun 21 2010 Kees Monshouwer <km|monshouwer_com> 0.8.2-1
- Added drop capability mode to drop capabilities permanent after set[ug]id
- Update to 0.8.2

* Thu May 27 2010 Kees Monshouwer <km|monshouwer_com> 0.8.1-1
- Changed module name to mod_ruid2
- Update to 0.8.1

* Mon Apr 12 2010 Kees Monshouwer <km|monshouwer_com> 0.8-1
- Update to 0.8

* Wed Oct 21 2009 Kees Monshouwer <km|monshouwer_com> 0.7.1-1
- Fixed security problem in config

* Sun Sep 27 2009 Kees Monshouwer <km|monshouwer_com> 0.7-1
- Added per directory config option

* Wed Aug 29 2007 Kees Monshouwer <km|monshouwer_com> 0.6-3.1
- Build for CentOS 5

* Fri Sep 07 2006 Kees Monshouwer <km|monshouwer_com> 0.6-3
- Fixed first child request groups bug

* Fri Sep 07 2006 Kees Monshouwer <km|monshouwer_com> 0.6-2
- Fixed some uninitalized vars and a typo
- Changed the default user and group to apache 

* Wed Mar 08 2006 Kees Monshouwer <km|monshouwer_com> 0.6-1
- Inital build for CentOS 4.2
