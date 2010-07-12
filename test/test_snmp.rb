require "test/unit"
require "net_snmp"

class TestNetsnmp < Test::Unit::TestCase
  def test_snmpv1
    man = NetSNMP::Manager.new(:version => :SNMPv1, :community => "public", :host => "localhost:8161", :retries => 2)
    response = man.get([1,3,6,1,2,1,1,1,0])
    assert_equal NetSNMP::SUCCESS, response.error_status
    assert_equal 1, response.varbind_list.length
    assert_equal '1.3.6.1.2.1.1.1.0', response.varbind_list.first.name.to_s
    man.close
  end
  
  def test_snmpv1_get
    man = NetSNMP::Manager.new(:version => :SNMPv1, :host => "localhost:8161", :community => "lpublic")
    response = man.get("sysName.0")
    assert man.version == :SNMPv1
    assert_equal NetSNMP::SUCCESS, response.error_status
    assert_equal 1, response.varbind_list.length
    assert_equal '1.3.6.1.2.1.1.5.0', response.varbind_list.first.name.to_s
    response = man.get("sysDescr.0")
    assert_equal NetSNMP::SUCCESS, response.error_status
    assert_equal 1, response.varbind_list.length
    assert_equal "An SNMP computer", response.varbind_list[0].value
    man.close
  end
  
  def test_snmpv2_get
    man = NetSNMP::Manager.new(:version => :SNMPv2c, :host => "localhost:8161", :community => "lpublic")
    response = man.get("sysName.0")
    assert man.version == :SNMPv2c
    assert_equal NetSNMP::SUCCESS, response.error_status
    assert_equal 1, response.varbind_list.length
    assert_equal '1.3.6.1.2.1.1.5.0', response.varbind_list.first.name.to_s
    man.close
  end
  
  def test_snmpv1_set
    man = NetSNMP::Manager.new(:version => :SNMPv1, :host => "localhost:8161", :community => "lpublic")
    response = man.set("sysLocation.0", "Somewhere")
    assert_equal NetSNMP::SUCCESS, response.error_status
    assert_equal 1, response.varbind_list.length
    assert_equal '1.3.6.1.2.1.1.6.0', response.varbind_list.first.name.to_s
    assert_equal "Somewhere", response.varbind_list.first.value.to_s
    response = man.get("sysLocation.0")
    assert_equal 1, response.varbind_list.length
    assert_equal '1.3.6.1.2.1.1.6.0', response.varbind_list.first.name.to_s
    assert_equal "Somewhere", response.varbind_list.first.value.to_s
    vb_list = response.varbind_list
    vb_list[0].value = "In a land far, far away"
    response = man.set(vb_list)
    assert_equal NetSNMP::SUCCESS, response.error_status
    assert_equal 1, response.varbind_list.length
    assert_equal "In a land far, far away", response.varbind_list.first.value.to_s
    assert_equal "In a land far, far away", man.get_value("sysLocation.0")
    man.close
  end
  
  def test_snmpv3_noauthnopriv
    man = NetSNMP::Manager.new(:version => :SNMPv3, 
                    :user => "ali_baba", 
                    :host => "localhost:8161",
                    :security_level => :authNoPriv,
                    :auth_protocol => :MD5,
                    :auth_pass_phrase => "open_sesame"
                    )

    assert man.version == :SNMPv3
    response = man.get("1.3.6.1.2.1.1.1.0")
    assert_equal NetSNMP::SUCCESS, response.error_status
    assert_equal 1, response.varbind_list.length
    assert response.varbind_list[0].value.is_a?(NetSNMP::OctetString)
    count = 0
    man.get("1.3.6.1.2.1.1.1.0").varbind_list.each {|vb| count += 1 }
    assert_equal 1, count
    count = 0
    man.get_next("1.3.6.1.2.1.1.1").varbind_list.each {|vb| count += 1 }
    assert_equal 1, count
    count = 0
    man.walk("1.3.6.1.2.1.1") {|vb| count += 1 }
    assert count > 5
    man.close
  end
  
  def test_snmpv3_wrongauth
    man = NetSNMP::Manager.new(:version => :SNMPv3, 
                    :user => "ali_baba", 
                    :host => "localhost:8161",
                    :security_level => :authNoPriv,
                    :auth_protocol => :SHA,
                    :auth_pass_phrase => "open_sesame"
                    )
    begin
      response = man.get("sysLocation.0")
      assert false
    rescue NetSNMP::SNMPException => e
      assert e.to_s =~ /Authentication/
    end
    
  end
  
  def test_snmpv3_authpriv
    man = NetSNMP::Manager.new(:host => "localhost:8161", 
                             :user => "authprivuser", 
                             :auth_protocol => :MD5,
                             :security_level => :authPriv, 
                             :auth_pass_phrase => "secret_secret", 
                             :version => :SNMPv3, 
                             :priv_protocol => :DES, 
                             :priv_pass_phrase => "super_secret")

    response = man.get("1.3.6.1.2.1.1.1.0")
    assert_equal NetSNMP::SUCCESS, response.error_status
    assert_equal 1, response.varbind_list.length
    assert response.varbind_list[0].value.is_a?(NetSNMP::OctetString)
  end
  
  def test_snmpv2c_get_bulk
    man = NetSNMP::Manager.new(:host => "localhost:8161", :community => "public", :version => :SNMPv2c)
    response = man.get_bulk("system", :max_repetitions => 10)
    assert_equal NetSNMP::SUCCESS, response.error_status
    assert_equal 10, response.varbind_list.length
    response = man.get_bulk("system", :max_repetitions => 1)
    assert_equal NetSNMP::SUCCESS, response.error_status
    assert_equal 1, response.varbind_list.length
  end
  
end
