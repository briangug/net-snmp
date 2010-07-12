# Example using SNMPv3
require 'rubygems'
require 'net_snmp'

# No Auth/No Priv
snmp = NetSNMP::Manager.new(:version => :SNMPv3, 
                :user => "authUser", 
                :host => "127.0.0.1",
                :security_level => :noAuthNoPriv
                )

puts f.get_value("1.3.6.1.2.1.1.1.0")
snmp.close

# authPriv mode
snmp = NetSNMP::Manager.new(:version => :SNMPv3, 
                :user => "modern_man", 
                :host => "127.0.0.1",
                :security_level => :authPriv,
                :auth_protocol => :SHA, # other option is :MD5
                :priv_protocol => :DES, # other option is :AES
                :auth_pass_phrase => "secret_secret",
                :priv_pass_phrase => "ive_got_a_secret"
                )

# Returns only the value
puts snmp.get_value("1.3.6.1.2.1.1.1.0")
# Returns an array of values
puts snmp.get_value(%w(sysName.0 sysLocation.0))
# the 'dump' method can be useful when using irb or script/console or for debugging.  
# It outputs the VarBind results to stdout.
snmp.get_bulk("system").dump

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

snmp.close
