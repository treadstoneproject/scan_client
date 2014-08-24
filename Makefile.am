# debug, optimized
AM_CXXFLAGS   = -I$(top_srcdir)/src/ -std=c++0x @AM_CXXFLAGS@

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
