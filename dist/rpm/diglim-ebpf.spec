name:           diglim-ebpf
Version:        0.1.0
Release:        1
Summary:        DIGLIM eBPF

Source0:        https://github.com/robertosassu/%{name}/archive/refs/tags/v%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
License:        GPLv2
Url:            https://github.com/robertosassu/diglim-ebpf
BuildRequires:  autoconf automake libtool libbpf-devel
BuildRequires:  bpftool dwarves clang kernel-devel rpm-devel glibc-devel
%if 0%{?suse_version}
BuildRequires:  libopenssl-devel glibc-devel-32bit libelf-devel
%else
BuildRequires:  openssl-devel glibc-devel(x86-32) elfutils-libelf-devel
%endif

BuildRequires:  dracut
Requires:       grubby

%description
This package contains the DIGLIM eBPF (user space and kernel space) and the
tools necessary for its management.

%prep
%autosetup -n %{name}-%{version} -p1

%build
autoreconf -iv
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%make_install %{?_smp_mflags}

%post
ldconfig

%postun
ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%dir %{_sysconfdir}/dracut.conf.d
%{_sysconfdir}/dracut.conf.d/diglim.conf
%{_prefix}/lib/systemd/system/diglim_user.service
%{_libdir}/libdiglim.so
%{_libdir}/libdiglimrpm.so
%exclude %{_libdir}/*.la
%exclude %{_libdir}/*.a
%{_libdir}/rpm-plugins/diglim.so
%exclude %{_libdir}/rpm-plugins/*.la
%exclude %{_libdir}/rpm-plugins/*.a
%dir %{_libdir}/diglim-parsers
%{_libdir}/diglim-parsers/*.so
%exclude %{_libdir}/diglim-parsers/*.la
%exclude %{_libdir}/diglim-parsers/*.a
%{_bindir}/diglim_user_client
%{_bindir}/compact_gen
%{_bindir}/rpm_gen
%{_bindir}/diglim_setup.sh
%{_sbindir}/diglim_user
%dir /usr/lib/dracut/modules.d/98diglim
%{_prefix}/lib/dracut/modules.d/98diglim/module-setup.sh
%{_prefix}/lib/dracut/modules.d/98diglim/load_digest_lists.sh
%{_datarootdir}/diglim-ebpf/ima-policy

%doc
%dir %{_datarootdir}/diglim-ebpf
%{_datarootdir}/diglim-ebpf/README.md
%{_datarootdir}/diglim-ebpf/compact_gen.txt
%{_datarootdir}/diglim-ebpf/rpm_gen.txt
%{_datarootdir}/diglim-ebpf/diglim_setup.sh.txt
%{_mandir}/man1/compact_gen.1.gz
%{_mandir}/man1/rpm_gen.1.gz
%{_mandir}/man1/diglim_setup.sh.1.gz


%changelog
* Thu Feb 17 2022 Roberto Sassu <roberto.sassu@huawei.com> - 0.1.0
- First public release
