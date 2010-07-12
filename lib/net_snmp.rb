require 'netsnmp/manager'
require 'netsnmp/object_types'
require 'netsnmp/pdu'
require 'netsnmp_api'

module NetSNMP
  VERSION = "0.2.0"
  SUCCESS = 0
  
  def self.compat(sym)
    Object.class_eval("#{sym.to_s} = NetSNMP")
  end
end
  
