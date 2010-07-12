# Copyright (C) 2010 Spiceworks, Inc.  All Rights Reserved.
module NetSNMP
  class Manager
    attr_reader :host, :version, :retries, :timeout
    
    class << self
      def open(config = {})
        manager = Manager.new(config)
        if block_given?
          begin
            yield manager
          ensure
            manager.close
          end
        end
      end
    end
    
    def varbind_list(object_ids, default_value = nil)
      default_value = nil if default_value == :NullValue
      list = VarBindList.new
      if object_ids.is_a?(OID)
        list << object_ids.to_varbind
      else
        Array(object_ids).each do |i|
          if i.respond_to?(:to_str)
            list << VarBind.new(Manager.create_oid(i), default_value) 
          else
            list << i.to_varbind
          end
        end
      end
      list
    end
    
    def walk(object_ids, index_column = 0, &block)
      vb_list = varbind_list(object_ids)
      raise ArgumentError, "index_column is past end of varbind list" if index_column >= vb_list.length

      is_single_vb = (vb_list.length == 1)
      start_list = vb_list
      start_oid = vb_list[index_column].name
      last_oid = start_oid
      loop do
        vb_list = (res = get_next(vb_list)).vb_list
        index_vb = vb_list[index_column]
        break if res.error_status != NetSNMP::SUCCESS || (index_vb.nil? || Null == index_vb.value || NoSuchObject == index_vb.value || EndOfMibView == index_vb.value)
        stop_oid = index_vb.name
        if stop_oid <= last_oid
          warn "OIDs are not increasing, #{last_oid} followed by #{stop_oid}"
          break
        end
        break unless stop_oid.subtree_of?(start_oid)
        last_oid = stop_oid
        if is_single_vb
          yield index_vb
        else
          vb_list = validate_row(vb_list, start_list, index_column)
          yield vb_list
        end
      end
    end
    
    def walk_bulk(start_oid, end_oid = nil, max_repetitions = 10, non_repeaters = 0)
      if start_oid.respond_to?(:to_str)
        cur_oid = Manager.create_oid(start_oid) 
      else
        cur_oid = start_oid
      end
      
      unless end_oid
        end_oid = Manager.create_oid(start_oid)
        end_oid[-1] = cur_oid.last + 1
      end
      
      while cur_oid < end_oid
        vb_list = (res = self.get_bulk(cur_oid, :max_repetitions => max_repetitions, 
                                       :non_repeaters => non_repeaters)).varbind_list
        if res.error_status == NetSNMP::SUCCESS && vb_list[0].name < end_oid && 
            (vb_list[0].value != Null && vb_list[0].value != NoSuchObject && vb_list[0].value != EndOfMibView)
          vb_list.each do |vb|
            break if vb.name >= end_oid
            yield vb
            cur_oid = vb.name
          end
        else
          break
        end
      end
    end
    
    def walk_range(start_oid, end_oid = nil, &block)
      if start_oid.respond_to?(:to_str)
        cur_oid = Manager.create_oid(start_oid) 
      else
        cur_oid = start_oid
      end
      
      unless end_oid
        end_oid = Manager.create_oid(start_oid)
        end_oid[-1] = cur_oid.last + 1
      end
      
      while cur_oid < end_oid
        vb_list = (res = self.get_next(cur_oid)).varbind_list
        if res.error_status == NetSNMP::SUCCESS && vb_list[0].name < end_oid && 
            (vb_list[0].value != Null && vb_list[0].value != NoSuchObject && vb_list[0].value != EndOfMibView)
          vb_list.each do |vb|
            yield vb
            cur_oid = vb.name
          end
        else
          break
        end
      end
    end
    
    # Explore wraps the walk_range call and prints the name/value results from
    # the walk.  Useful when using interactively.
    def explore(start_oid, end_oid = nil)
      walk_range(start_oid, end_oid) do |vb|
        puts "#{vb.name} = #{vb.value.asn1_type}: #{vb.value}"
      end
    end
    
    # Helper method for walk.  Checks all of the VarBinds in vb_list to
    # make sure that the row indices match.  If the row index does not
    # match the index column, then that varbind is replaced with a varbind
    # with a value of NoSuchInstance.
    def validate_row(vb_list, start_list, index_column)
      start_vb = start_list[index_column]
      index_vb = vb_list[index_column]
      row_index = index_vb.name.index(start_vb.name)
      vb_list.each_index do |i|
        if i != index_column
          expected_oid = start_list[i].name + row_index 
          if vb_list[i].name != expected_oid
            vb_list[i] = VarBind.new(expected_oid, NetSNMP::NoSuchInstance)
          end
        end
      end
      vb_list
    end
    private :validate_row

  end #Manager
end #module
