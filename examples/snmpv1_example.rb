# Example using the Net-SNMP library in SNMPv1 mode

require 'rubygems'
require 'net_snmp'

snmp = NetSNMP::Manager.new(:host => "127.0.0.1", :community => "public", :version => :SNMPv1, :retries => 3, :timeout => 4)
sysDescr = snmp.get_value("1.3.6.1.2.1.1.1.0")

puts "System Description: #{sysDescr}"

#
# SNMP Set examples
# =================
#
#-Variation 1: name, value pair.  Good for data types that match default Ruby ones.
#              (String, Integer)
#response = snmp.set("sysContact.0", "admin@example.com")
#puts "Set fields" if response.error_code == NetSNMP::SUCCESS
#
#-Variation 2: Using a VarBind object.  Good when you want to explicity set the data type.
#vb = NetSNMP::VarBind.new("sysContact.0")
#vb.value = NetSNMP::OctetString.new("admin@example.com")
#response = snmp.set(vb)
#puts "Set fields" if response.error_code == NetSNMP::SUCCESS
#
#-Variation 3: name, typed value pair.
#response = snmp.set("sysContact.0", NetSNMP::OctetString.new("admin@example.com"))
#puts "Set fields" if response.error_code == NetSNMP::SUCCESS
#
#-Variation 4: Setting multiple values using VarBinds
#vb = NetSNMP::VarBind.new("sysContact.0", "admin@example.com")
#vb2 = NetSNMP::VarBind.new("sysDescr.0", "This is a test.  This is only a test.")
#reponse = snmp.set([vb, vb2])
#puts "Set fields" if response.error_code == NetSNMP::SUCCESS
