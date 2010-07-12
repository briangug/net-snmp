
task :compile do
 pwd=Dir.pwd
 begin
   Dir.chdir("ext/netsnmp_api")
   puts `ruby extconf.rb`
   puts `make clean; make`
 ensure
   Dir.chdir(pwd)
 end
end

task :start_snmpd do
  $snmpd_pid = Kernel.fork()
  if ($snmpd_pid.nil?)
    exec("snmpd -Lf./test/snmpd.log -LE 0 -C -c ./test/snmpd-2.conf -r -f udp:127.0.0.1:8161")
  end
end

task :stop_snmpd do
  `kill #{$snmp_pid}` if $snmpd_pid
end

task :test => [:start_snmpd]

END {
  cmd = "kill #{$snmpd_pid}"
  system(cmd) if $snmpd_pid
}