# Copyright (C) 2010 Spiceworks, Inc.  All Rights Reserved.
module NetSNMP
  #
  # == PDU
  #
  # The PDU is the response from an SNMP action.
  #
  class PDU
    attr_reader :varbind_list, :error_status

    def initialize(request_id, varbind_list, error_status = 0)
      @request_id = request_id
      @varbind_list = varbind_list
      @error_status = error_status
    end
  
    #
    # Iterator for each VarBind object in this PDU
    #
    def each_varbind(&block)
      (@varbind_list || []).each do |vb|
        yield vb
      end
    end
  
    # Outputs the request ID, error text (if any), and each VarBind to stdout.
    def dump
      error = ""
      error = "\t\tERROR: #{error_description}" if error_status != 0
      puts "Request ID: #{@request_id}#{error}"
      @varbind_list.dump if @varbind_list
    end
    
    #
    # Returns the array of VarBind objects associated with this PDU
    #
    def vb_list
      @varbind_list
    end

    #
    # Returns a description for the error_status
    #
    def error_description
      NetSNMP::Manager.error_description(self.error_status)
    end
    
  end #PDU

end #module