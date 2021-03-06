require 'mkmf'

dir_config("netsnmp")
dir_config("netsnmpconfig")
dir_config("openssl")
have_header("net-snmp/net-snmp-config.h")
if have_func('rb_thread_blocking_region') and have_macro('RUBY_UBF_IO', 'ruby.h')
 $CFLAGS += " -DHAVE_TBR "
 $CPPFLAGS += " -DHAVE_TBR "
end
# This will error on include because it wants net-snmp-config.h included before it. 
#have_header("net-snmp/net-snmp-includes.h")
have_library("netsnmp", "init_snmp")
create_makefile("netsnmp_api")