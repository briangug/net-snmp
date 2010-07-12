= NetSNMP/Ruby Interface

* http://rubyforge.org/projects/netsnmp

== DESCRIPTION

This gem is a wrapper around the Net-SNMP library.  It supports SNMP versions 1, 2c, and 3.

== FEATURES/PROBLEMS:

* SNMP Versions 1, 2c, and 3

== SYNOPSIS:

  require 'net_snmp'
  
  manager = NetSNMP::Manager.new(:host => "localhost", :version => :SNMPv1, :community => "public", :timeout => 3)
  response = manager.get("1.3.6.1.2.1.1.1.0")
  if response.error_status == NetSNMP::SUCCESS
    response.each_varbind {|vb| puts "#{vb.name}: #{vb.value}"}
  else
    puts response.error_description
  end

== REQUIREMENTS:

* Net-SNMP library

== INSTALL:

* sudo gem install netsnmp

== LICENSE:

This SNMP Library is Copyright (c) 2010 by Spiceworks, Inc.  All Rights Reserved.  http://www.spiceworks.com
It is free software.  Redistribution is permitted under the same terms and conditions
as the standard Ruby distribution.  See the COPYING file in the Ruby distribution for details.

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.
