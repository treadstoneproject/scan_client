# Makefile.in generated by automake 1.11.3 from Makefile.am.
# src/internet/scan_client/Makefile.  Generated from Makefile.in by configure.

# Copyright (C) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002,
# 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Free Software
# Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.





pkgdatadir = $(datadir)/avanalysis-tools
pkgincludedir = $(includedir)/avanalysis-tools
pkglibdir = $(libdir)/avanalysis-tools
pkglibexecdir = $(libexecdir)/avanalysis-tools
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
subdir = src/internet/scan_client
DIST_COMMON = $(libscan_client_a_HEADERS) $(srcdir)/Makefile.am \
	$(srcdir)/Makefile.in
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/configure.ac
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
mkinstalldirs = $(install_sh) -d
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
CONFIG_CLEAN_VPATH_FILES =
am__vpath_adj_setup = srcdirstrip=`echo "$(srcdir)" | sed 's|.|.|g'`;
am__vpath_adj = case $$p in \
    $(srcdir)/*) f=`echo "$$p" | sed "s|^$$srcdirstrip/||"`;; \
    *) f=$$p;; \
  esac;
am__strip_dir = f=`echo $$p | sed -e 's|^.*/||'`;
am__install_max = 40
am__nobase_strip_setup = \
  srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*|]/\\\\&/g'`
am__nobase_strip = \
  for p in $$list; do echo "$$p"; done | sed -e "s|$$srcdirstrip/||"
am__nobase_list = $(am__nobase_strip_setup); \
  for p in $$list; do echo "$$p $$p"; done | \
  sed "s| $$srcdirstrip/| |;"' / .*\//!s/ .*/ ./; s,\( .*\)/[^/]*$$,\1,' | \
  $(AWK) 'BEGIN { files["."] = "" } { files[$$2] = files[$$2] " " $$1; \
    if (++n[$$2] == $(am__install_max)) \
      { print $$2, files[$$2]; n[$$2] = 0; files[$$2] = "" } } \
    END { for (dir in files) print dir, files[dir] }'
am__base_list = \
  sed '$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;s/\n/ /g' | \
  sed '$$!N;$$!N;$$!N;$$!N;s/\n/ /g'
am__uninstall_files_from_dir = { \
  test -z "$$files" \
    || { test ! -d "$$dir" && test ! -f "$$dir" && test ! -r "$$dir"; } \
    || { echo " ( cd '$$dir' && rm -f" $$files ")"; \
         $(am__cd) "$$dir" && rm -f $$files; }; \
  }
am__installdirs = "$(DESTDIR)$(libdir)" \
	"$(DESTDIR)$(libscan_client_adir)"
LIBRARIES = $(lib_LIBRARIES)
AR = ar
ARFLAGS = cru
libscan_client_a_AR = $(AR) $(ARFLAGS)
libscan_client_a_LIBADD =
am__objects_1 =
am_libscan_client_a_OBJECTS = $(am__objects_1) scan_client.$(OBJEXT) \
	basic_scan_dir.$(OBJEXT) basic_scan_dir_service.$(OBJEXT) \
	scan_dir_impl.$(OBJEXT) packedmessage_scan_client.$(OBJEXT) \
	message_scan.pb.$(OBJEXT) logging.$(OBJEXT) \
	stringprintf.$(OBJEXT)
libscan_client_a_OBJECTS = $(am_libscan_client_a_OBJECTS)
DEFAULT_INCLUDES = -I. -I$(top_builddir)
depcomp = $(SHELL) $(top_srcdir)/build-aux/depcomp
am__depfiles_maybe = depfiles
am__mv = mv -f
CXXCOMPILE = $(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS)
CXXLD = $(CXX)
CXXLINK = $(CXXLD) $(AM_CXXFLAGS) $(CXXFLAGS) $(AM_LDFLAGS) $(LDFLAGS) \
	-o $@
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
SOURCES = $(libscan_client_a_SOURCES)
DIST_SOURCES = $(libscan_client_a_SOURCES)
HEADERS = $(libscan_client_a_HEADERS)
ETAGS = etags
CTAGS = ctags
DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
ACLOCAL = ${SHELL} /home/chatsiri/workspacecpp/pthread_sync_ocl/build-aux/missing --run aclocal-1.11
AMTAR = $${TAR-tar}
AM_CFLAGS = 

# debug, optimized
AM_CXXFLAGS = -I$(top_srcdir)/src/ -std=c++0x 
AM_LDFLAGS = 
AUTOCONF = ${SHELL} /home/chatsiri/workspacecpp/pthread_sync_ocl/build-aux/missing --run autoconf
AUTOHEADER = ${SHELL} /home/chatsiri/workspacecpp/pthread_sync_ocl/build-aux/missing --run autoheader
AUTOMAKE = ${SHELL} /home/chatsiri/workspacecpp/pthread_sync_ocl/build-aux/missing --run automake-1.11
AWK = gawk
CPPFLAGS = -I/home/chatsiri/workspacecpp/gtest-1.6.0/include -I/home/chatsiri/workspacecpp/boost-truck -I/home/chatsiri/sda1/workspacecpp/clamav-devel-hnmav/ -I/home/chatsiri/workspacecpp/tbb/tbb41_20121003oss/include -I/home/chatsiri/sda1/workspacecpp/protobuf-2.5.0/build/include
CXX = g++
CXXCPP = g++ -E
CXXDEPMODE = depmode=gcc3
CXXFLAGS = -g -O2
CYGPATH_W = echo
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /bin/grep -E
EXEEXT = 
GREP = /bin/grep
INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
LDFLAGS = -L/home/chatsiri/workspacecpp/gtest-1.6.0/lib -L/home/chatsiri/workspacecpp/boost-truck/stage/lib -L/usr/lib64 -L/home/chatsiri/sda1/workspacecpp/clamav-devel-hnmav/build/lib -L/home/chatsiri/workspacecpp/tbb/tbb41_20121003oss/build/linux_intel64_gcc_cc4.6_libc2.15_kernel3.2.0_debug -L/home/chatsiri/sda1/workspacecpp/protobuf-2.5.0/build/lib
LIBOBJS = 
LIBS = -lgtest -lboost_thread -lpthread -lboost_system -lboost_program_options -lboost_log -lboost_filesystem -lboost_timer -lOpenCL -lrt -lclamav -lprotobuf 
LTLIBOBJS = 
MAKEINFO = ${SHELL} /home/chatsiri/workspacecpp/pthread_sync_ocl/build-aux/missing --run makeinfo
MKDIR_P = /bin/mkdir -p
OBJEXT = o
PACKAGE = avanalysis-tools
PACKAGE_BUGREPORT = rchatsiri@hnmav.io
PACKAGE_NAME = hnmav
PACKAGE_STRING = hnmav 0.1
PACKAGE_TARNAME = avanalysis-tools
PACKAGE_URL = http://www.hnmav.io
PACKAGE_VERSION = 0.1
PATH_SEPARATOR = :
RANLIB = ranlib
SET_MAKE = 
SHELL = /bin/bash
STRIP = 
VERSION = 0.1
abs_builddir = /home/chatsiri/workspacecpp/pthread_sync_ocl/src/internet/scan_client
abs_srcdir = /home/chatsiri/workspacecpp/pthread_sync_ocl/src/internet/scan_client
abs_top_builddir = /home/chatsiri/workspacecpp/pthread_sync_ocl
abs_top_srcdir = /home/chatsiri/workspacecpp/pthread_sync_ocl
ac_ct_CXX = g++
am__include = include
am__leading_dot = .
am__quote = 
am__tar = $${TAR-tar} chof - "$$tardir"
am__untar = $${TAR-tar} xf -
bindir = ${exec_prefix}/bin
build_alias = 
builddir = .
datadir = ${datarootdir}
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}
dvidir = ${docdir}
exec_prefix = ${prefix}
host_alias = 
htmldir = ${docdir}
includedir = ${prefix}/include
infodir = ${datarootdir}/info
install_sh = ${SHELL} /home/chatsiri/workspacecpp/pthread_sync_ocl/build-aux/install-sh
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
mandir = ${datarootdir}/man
mkdir_p = /bin/mkdir -p
oldincludedir = /usr/include
pdfdir = ${docdir}
prefix = /usr/local
program_transform_name = s,x,x,
psdir = ${docdir}
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
srcdir = .
sysconfdir = ${prefix}/etc
target_alias = 
top_build_prefix = ../../../
top_builddir = ../../..
top_srcdir = ../../..

# Make src file 
# libarries connect to internet client mode.
lib_LIBRARIES = libscan_client.a

#@install header to system
libscan_client_adir = $(includedir)/internet/scan_client

#Header
libscan_client_a_HEADERS = scan_client.hpp \
scan_dir.hpp \
basic_scan_dir.hpp \
basic_scan_dir_service.hpp \
scan_dir_impl.hpp \
packedmessage_scan_client.hpp \
../msg/scan_server_client/message_scan.pb.h \
../logger/logging.hpp \
../logger/stringprintf.hpp


# ../msg/scan_server_client/message_scan.bp.cc 

# library
libscan_client_a_SOURCES = $(libscan_client_a_HEADERS) scan_client.cpp \
basic_scan_dir.cpp \
basic_scan_dir_service.cpp \
scan_dir_impl.cpp \
packedmessage_scan_client.cpp \
../msg/scan_server_client/message_scan.pb.cc \
../logger/logging.cpp \
../logger/stringprintf.cpp

all: all-am

.SUFFIXES:
.SUFFIXES: .cc .cpp .o .obj
$(srcdir)/Makefile.in:  $(srcdir)/Makefile.am  $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      ( cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh ) \
	        && { if test -f $@; then exit 0; else break; fi; }; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --foreign src/internet/scan_client/Makefile'; \
	$(am__cd) $(top_srcdir) && \
	  $(AUTOMAKE) --foreign src/internet/scan_client/Makefile
.PRECIOUS: Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe);; \
	esac;

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh

$(top_srcdir)/configure:  $(am__configure_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(ACLOCAL_M4):  $(am__aclocal_m4_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(am__aclocal_m4_deps):
install-libLIBRARIES: $(lib_LIBRARIES)
	@$(NORMAL_INSTALL)
	test -z "$(libdir)" || $(MKDIR_P) "$(DESTDIR)$(libdir)"
	@list='$(lib_LIBRARIES)'; test -n "$(libdir)" || list=; \
	list2=; for p in $$list; do \
	  if test -f $$p; then \
	    list2="$$list2 $$p"; \
	  else :; fi; \
	done; \
	test -z "$$list2" || { \
	  echo " $(INSTALL_DATA) $$list2 '$(DESTDIR)$(libdir)'"; \
	  $(INSTALL_DATA) $$list2 "$(DESTDIR)$(libdir)" || exit $$?; }
	@$(POST_INSTALL)
	@list='$(lib_LIBRARIES)'; test -n "$(libdir)" || list=; \
	for p in $$list; do \
	  if test -f $$p; then \
	    $(am__strip_dir) \
	    echo " ( cd '$(DESTDIR)$(libdir)' && $(RANLIB) $$f )"; \
	    ( cd "$(DESTDIR)$(libdir)" && $(RANLIB) $$f ) || exit $$?; \
	  else :; fi; \
	done

uninstall-libLIBRARIES:
	@$(NORMAL_UNINSTALL)
	@list='$(lib_LIBRARIES)'; test -n "$(libdir)" || list=; \
	files=`for p in $$list; do echo $$p; done | sed -e 's|^.*/||'`; \
	dir='$(DESTDIR)$(libdir)'; $(am__uninstall_files_from_dir)

clean-libLIBRARIES:
	-test -z "$(lib_LIBRARIES)" || rm -f $(lib_LIBRARIES)
libscan_client.a: $(libscan_client_a_OBJECTS) $(libscan_client_a_DEPENDENCIES) $(EXTRA_libscan_client_a_DEPENDENCIES) 
	-rm -f libscan_client.a
	$(libscan_client_a_AR) libscan_client.a $(libscan_client_a_OBJECTS) $(libscan_client_a_LIBADD)
	$(RANLIB) libscan_client.a

mostlyclean-compile:
	-rm -f *.$(OBJEXT)

distclean-compile:
	-rm -f *.tab.c

include ./$(DEPDIR)/basic_scan_dir.Po
include ./$(DEPDIR)/basic_scan_dir_service.Po
include ./$(DEPDIR)/logging.Po
include ./$(DEPDIR)/message_scan.pb.Po
include ./$(DEPDIR)/packedmessage_scan_client.Po
include ./$(DEPDIR)/scan_client.Po
include ./$(DEPDIR)/scan_dir_impl.Po
include ./$(DEPDIR)/stringprintf.Po

.cc.o:
	$(CXXCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CXXDEPMODE) $(depcomp) \
#	$(CXXCOMPILE) -c -o $@ $<

.cc.obj:
	$(CXXCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ `$(CYGPATH_W) '$<'`
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CXXDEPMODE) $(depcomp) \
#	$(CXXCOMPILE) -c -o $@ `$(CYGPATH_W) '$<'`

message_scan.pb.o: ../msg/scan_server_client/message_scan.pb.cc
	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -MT message_scan.pb.o -MD -MP -MF $(DEPDIR)/message_scan.pb.Tpo -c -o message_scan.pb.o `test -f '../msg/scan_server_client/message_scan.pb.cc' || echo '$(srcdir)/'`../msg/scan_server_client/message_scan.pb.cc
	$(am__mv) $(DEPDIR)/message_scan.pb.Tpo $(DEPDIR)/message_scan.pb.Po
#	source='../msg/scan_server_client/message_scan.pb.cc' object='message_scan.pb.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CXXDEPMODE) $(depcomp) \
#	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -c -o message_scan.pb.o `test -f '../msg/scan_server_client/message_scan.pb.cc' || echo '$(srcdir)/'`../msg/scan_server_client/message_scan.pb.cc

message_scan.pb.obj: ../msg/scan_server_client/message_scan.pb.cc
	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -MT message_scan.pb.obj -MD -MP -MF $(DEPDIR)/message_scan.pb.Tpo -c -o message_scan.pb.obj `if test -f '../msg/scan_server_client/message_scan.pb.cc'; then $(CYGPATH_W) '../msg/scan_server_client/message_scan.pb.cc'; else $(CYGPATH_W) '$(srcdir)/../msg/scan_server_client/message_scan.pb.cc'; fi`
	$(am__mv) $(DEPDIR)/message_scan.pb.Tpo $(DEPDIR)/message_scan.pb.Po
#	source='../msg/scan_server_client/message_scan.pb.cc' object='message_scan.pb.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CXXDEPMODE) $(depcomp) \
#	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -c -o message_scan.pb.obj `if test -f '../msg/scan_server_client/message_scan.pb.cc'; then $(CYGPATH_W) '../msg/scan_server_client/message_scan.pb.cc'; else $(CYGPATH_W) '$(srcdir)/../msg/scan_server_client/message_scan.pb.cc'; fi`

logging.o: ../logger/logging.cpp
	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -MT logging.o -MD -MP -MF $(DEPDIR)/logging.Tpo -c -o logging.o `test -f '../logger/logging.cpp' || echo '$(srcdir)/'`../logger/logging.cpp
	$(am__mv) $(DEPDIR)/logging.Tpo $(DEPDIR)/logging.Po
#	source='../logger/logging.cpp' object='logging.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CXXDEPMODE) $(depcomp) \
#	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -c -o logging.o `test -f '../logger/logging.cpp' || echo '$(srcdir)/'`../logger/logging.cpp

logging.obj: ../logger/logging.cpp
	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -MT logging.obj -MD -MP -MF $(DEPDIR)/logging.Tpo -c -o logging.obj `if test -f '../logger/logging.cpp'; then $(CYGPATH_W) '../logger/logging.cpp'; else $(CYGPATH_W) '$(srcdir)/../logger/logging.cpp'; fi`
	$(am__mv) $(DEPDIR)/logging.Tpo $(DEPDIR)/logging.Po
#	source='../logger/logging.cpp' object='logging.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CXXDEPMODE) $(depcomp) \
#	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -c -o logging.obj `if test -f '../logger/logging.cpp'; then $(CYGPATH_W) '../logger/logging.cpp'; else $(CYGPATH_W) '$(srcdir)/../logger/logging.cpp'; fi`

stringprintf.o: ../logger/stringprintf.cpp
	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -MT stringprintf.o -MD -MP -MF $(DEPDIR)/stringprintf.Tpo -c -o stringprintf.o `test -f '../logger/stringprintf.cpp' || echo '$(srcdir)/'`../logger/stringprintf.cpp
	$(am__mv) $(DEPDIR)/stringprintf.Tpo $(DEPDIR)/stringprintf.Po
#	source='../logger/stringprintf.cpp' object='stringprintf.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CXXDEPMODE) $(depcomp) \
#	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -c -o stringprintf.o `test -f '../logger/stringprintf.cpp' || echo '$(srcdir)/'`../logger/stringprintf.cpp

stringprintf.obj: ../logger/stringprintf.cpp
	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -MT stringprintf.obj -MD -MP -MF $(DEPDIR)/stringprintf.Tpo -c -o stringprintf.obj `if test -f '../logger/stringprintf.cpp'; then $(CYGPATH_W) '../logger/stringprintf.cpp'; else $(CYGPATH_W) '$(srcdir)/../logger/stringprintf.cpp'; fi`
	$(am__mv) $(DEPDIR)/stringprintf.Tpo $(DEPDIR)/stringprintf.Po
#	source='../logger/stringprintf.cpp' object='stringprintf.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CXXDEPMODE) $(depcomp) \
#	$(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS) -c -o stringprintf.obj `if test -f '../logger/stringprintf.cpp'; then $(CYGPATH_W) '../logger/stringprintf.cpp'; else $(CYGPATH_W) '$(srcdir)/../logger/stringprintf.cpp'; fi`

.cpp.o:
	$(CXXCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CXXDEPMODE) $(depcomp) \
#	$(CXXCOMPILE) -c -o $@ $<

.cpp.obj:
	$(CXXCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ `$(CYGPATH_W) '$<'`
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CXXDEPMODE) $(depcomp) \
#	$(CXXCOMPILE) -c -o $@ `$(CYGPATH_W) '$<'`
install-libscan_client_aHEADERS: $(libscan_client_a_HEADERS)
	@$(NORMAL_INSTALL)
	test -z "$(libscan_client_adir)" || $(MKDIR_P) "$(DESTDIR)$(libscan_client_adir)"
	@list='$(libscan_client_a_HEADERS)'; test -n "$(libscan_client_adir)" || list=; \
	for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  echo "$$d$$p"; \
	done | $(am__base_list) | \
	while read files; do \
	  echo " $(INSTALL_HEADER) $$files '$(DESTDIR)$(libscan_client_adir)'"; \
	  $(INSTALL_HEADER) $$files "$(DESTDIR)$(libscan_client_adir)" || exit $$?; \
	done

uninstall-libscan_client_aHEADERS:
	@$(NORMAL_UNINSTALL)
	@list='$(libscan_client_a_HEADERS)'; test -n "$(libscan_client_adir)" || list=; \
	files=`for p in $$list; do echo $$p; done | sed -e 's|^.*/||'`; \
	dir='$(DESTDIR)$(libscan_client_adir)'; $(am__uninstall_files_from_dir)

ID: $(HEADERS) $(SOURCES) $(LISP) $(TAGS_FILES)
	list='$(SOURCES) $(HEADERS) $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	mkid -fID $$unique
tags: TAGS

TAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	set x; \
	here=`pwd`; \
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	shift; \
	if test -z "$(ETAGS_ARGS)$$*$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  if test $$# -gt 0; then \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      "$$@" $$unique; \
	  else \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      $$unique; \
	  fi; \
	fi
ctags: CTAGS
CTAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	test -z "$(CTAGS_ARGS)$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && $(am__cd) $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) "$$here"

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags

distdir: $(DISTFILES)
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	case $$dist_files in \
	  */*) $(MKDIR_P) `echo "$$dist_files" | \
			   sed '/\//!d;s|^|$(distdir)/|;s,/[^/]*$$,,' | \
			   sort -u` ;; \
	esac; \
	for file in $$dist_files; do \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  if test -d $$d/$$file; then \
	    dir=`echo "/$$file" | sed -e 's,/[^/]*$$,,'`; \
	    if test -d "$(distdir)/$$file"; then \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -fpR $(srcdir)/$$file "$(distdir)$$dir" || exit 1; \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    cp -fpR $$d/$$file "$(distdir)$$dir" || exit 1; \
	  else \
	    test -f "$(distdir)/$$file" \
	    || cp -p $$d/$$file "$(distdir)/$$file" \
	    || exit 1; \
	  fi; \
	done
check-am: all-am
check: check-am
all-am: Makefile $(LIBRARIES) $(HEADERS)
installdirs:
	for dir in "$(DESTDIR)$(libdir)" "$(DESTDIR)$(libscan_client_adir)"; do \
	  test -z "$$dir" || $(MKDIR_P) "$$dir"; \
	done
install: install-am
install-exec: install-exec-am
install-data: install-data-am
uninstall: uninstall-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-am
install-strip:
	if test -z '$(STRIP)'; then \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	      install; \
	else \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	    "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'" install; \
	fi
mostlyclean-generic:

clean-generic:

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
clean: clean-am

clean-am: clean-generic clean-libLIBRARIES mostlyclean-am

distclean: distclean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
distclean-am: clean-am distclean-compile distclean-generic \
	distclean-tags

dvi: dvi-am

dvi-am:

html: html-am

html-am:

info: info-am

info-am:

install-data-am: install-libscan_client_aHEADERS

install-dvi: install-dvi-am

install-dvi-am:

install-exec-am: install-libLIBRARIES

install-html: install-html-am

install-html-am:

install-info: install-info-am

install-info-am:

install-man:

install-pdf: install-pdf-am

install-pdf-am:

install-ps: install-ps-am

install-ps-am:

installcheck-am:

maintainer-clean: maintainer-clean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic

pdf: pdf-am

pdf-am:

ps: ps-am

ps-am:

uninstall-am: uninstall-libLIBRARIES uninstall-libscan_client_aHEADERS

.MAKE: install-am install-strip

.PHONY: CTAGS GTAGS all all-am check check-am clean clean-generic \
	clean-libLIBRARIES ctags distclean distclean-compile \
	distclean-generic distclean-tags distdir dvi dvi-am html \
	html-am info info-am install install-am install-data \
	install-data-am install-dvi install-dvi-am install-exec \
	install-exec-am install-html install-html-am install-info \
	install-info-am install-libLIBRARIES \
	install-libscan_client_aHEADERS install-man install-pdf \
	install-pdf-am install-ps install-ps-am install-strip \
	installcheck installcheck-am installdirs maintainer-clean \
	maintainer-clean-generic mostlyclean mostlyclean-compile \
	mostlyclean-generic pdf pdf-am ps ps-am tags uninstall \
	uninstall-am uninstall-libLIBRARIES \
	uninstall-libscan_client_aHEADERS


# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
