# Copyright (C) 2010 Spiceworks, Inc.  All Rights Reserved.
module NetSNMP
  
  class VarBindList < Array
    include Comparable

    def asn1_type
      "VarBindList"
    end
    
    # Utility to output all the varbinds
    def dump
      self.each do |vb|
        puts "#{vb.name} = #{vb.value.asn1_type}: #{vb.value}"
      end
      nil
    end
  end

  # The ASN_TYPE values must match the ASN_xxxx values in asn1.h

  class OctetString < String
    ASN_TYPE = 0x04
    
    def asn1_type
      "Octet String"
    end
    
    # Creates a human readable string for a MacAddress
    # field.
    # * sep The separator character
    # * uppercase Whether to uppercase the hex digits
    def to_mac_s(sep = ":", uppercase = true)
      mac = ""
      mac_format = "%2.2X" if uppercase
      mac_format = "%2.2x" unless uppercase
      
      if self.length == 6
        (0..5).each do |i|
           mac << sep if i > 0
           mac << (mac_format % self[i])
        end
      end
      mac
    end
  end

  class Integer
    include Comparable
    
    ASN_TYPE = 0x02
    
    def initialize(val)
      @value = val
    end
    
    def asn1_type
      "Integer"
    end
    
    def <=>(other)
        @value <=> other.to_i
    end
    
    def to_i
      @value.to_i
    end
    
    def to_s
      @value.to_s
    end
  end

  class UnsignedInteger < Integer
    ASN_TYPE = 0x42
    def asn1_type
      "Unsigned Integer"
    end
  end
  
  class Gauge < UnsignedInteger
    ASN_TYPE = 0x42
    
    def asn1_type
      "Gauge"
    end
  end
  
  class IpAddress 
    ASN_TYPE = 0x40
    
    def asn1_type
      "IpAddress"
    end
    
    def initialize(str)
      ip = str.to_s
      ip = parse_ip(ip) if ip.length > 4
      raise "Invalid IP address: #{str}" if ip.length != 4
      @value = ip
    end
    
    def to_s
      octets = []
      @value.each_byte { |b| octets << b.to_i }
      octets.join(".")
    end
    
    private
    def parse_ip(ip)
      parsed = ""
      pieces = ip.split(".")
      if pieces.length == 4
        pieces.each { |p| parsed << p.to_i }
      end
      parsed
    end
  end #IpAddress
  
  class Integer64
    attr_accessor :value
    
    ASN_TYPE = 0x4a
    
    def asn1_type
      "Integer64"
    end
    
    def initialize(val)
      @value = val
    end
    
    def to_i
      @value.to_i
    end
    
    def to_s
      @value.to_s
    end
  end
  
  class Counter32 < Integer
    ASN_TYPE = 0x41
    
    def asn1_type
      "Counter32"
    end
  end
  
  class Counter64 < Integer64
    ASN_TYPE = 0x46
    
    def asn1_type
      "Counter64"
    end
  end
  
  class Float
    attr_accessor :value
    
    ASN_TYPE = 0x48
    
    def asn1_type
      "Float"
    end
    
    def initialize(val)
      @value = val.to_f
    end

    def to_i
      @value.to_i
    end
    
    def to_f
      @value.to_f
    end
    
    def to_s
      @value.to_s
    end
  end

  class Double < Float
    ASN_TYPE = 0x49
    
    def asn1_type
      "Opaque Double"
    end
  end
  
  #
  # The VarBind wraps an OID (Name)/Value pair.
  class VarBind
    attr_reader :name
    attr_accessor :value
    
    def initialize(var_name, var_value = nil)
      if var_name.respond_to?(:to_str)
        @name = OID.create(var_name.to_str)
      else
        @name = var_name
      end
      @value = var_value
    end
    
    def to_varbind
      return self
    end
    
    def to_s
      @value.to_s
    end
    
    def each
      yield self
    end
    
    def asn1_type
      "VarBind"
    end
  end
  
  #
  # OID class wraps the Object Identifier used for retrieving or setting values
  #
  class OID < Array
    include Comparable

    ASN_TYPE = 0x06
    
    def asn1_type
      "Object Identifier"
    end
    
    def to_s
      self.join(".")
    end
    
    # Creates an OID from a string, integer array.  String values may use
    # MIB names if the MIB is loaded (e.g., sysDescr.0)
    def self.create(oid)
      r = nil
      if oid.respond_to?(:to_ary)
        r = self.new(oid) 
      else
        r = self.new(Manager.create_oid(oid.to_s))
      end
      r
    end

    def subtree_of?(parent_tree)
        if parent_tree.length > self.length
            false
        else
            parent_tree.each_index do |i|
                return false if parent_tree[i] != self[i]
            end
            true
        end
    end
    
    def to_varbind
      VarBind.new(self, self)
    end
    
    def value
      self.to_s
    end
    
    def index(parent_tree)
      parent_tree = OID.create(parent_tree) unless parent_tree.is_a?(OID)
      if not subtree_of?(parent_tree)
        raise ArgumentError, "#{self.to_s} not a subtree of #{parent_tree.to_s}"
      elsif self.length == parent_tree.length
        raise ArgumentError, "OIDs are the same"
      else
        OID.new(self[parent_tree.length..-1])
      end
    end
    
  end #OID
  
  class TimeTicks
    attr_accessor :value
    
    ASN_TYPE = 0x43
    
    def initialize(ticks)
      @value = ticks
    end
    
    def asn1_type
      "TimeTicks"
    end
    
    def to_i
      @value.to_i
    end
    
    def to_s
      days, remainder = @value.divmod(8640000)
      hours, remainder = remainder.divmod(360000)
      minutes, remainder = remainder.divmod(6000)
      seconds, hundredths = remainder.divmod(100)
      v = ""
      case
        when days < 1
          v = sprintf('%02d:%02d:%02d.%02d', hours, minutes, seconds, hundredths)
        when days == 1
          v = sprintf('1 day, %02d:%02d:%02d.%02d', hours, minutes, seconds, hundredths)
        when days > 1
          v = sprintf('%d days, %02d:%02d:%02d.%02d', days, hours, minutes, seconds, hundredths)
      end
      "(#{@value}) #{v}"
    end
    
  end #TimeTicks
  
  class NoSuchInstance
    class << self
      def asn1_type
        "noSuchInstance"
      end
    
      def to_s
        asn1_type
      end
    end
  end
  
  class NoSuchObject
    class << self
      def asn1_type
        "noSuchObject"
      end
    
      def to_s
        asn1_type
      end
    end
  end
  
  class Null
    ASN_TYPE = 0x05
    
    class << self
      def asn1_type
        "Null"
      end
    
      def to_s
        asn1_type
      end
    end
  end
  
  class EndOfMibView
    class << self
      def asn1_type
        "endOfMibView"
      end
      
      def to_s
        asn1_type
      end
    end
  end
  
  class SNMPException < RuntimeError
  end
  
  class RequestTimeout < RuntimeError
  end
  
end #module