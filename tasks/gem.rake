begin
require 'rubygems/package_task'
rescue Exception => e
 # 1.9?
end
require 'hoe'

HOE = Hoe.spec 'net-snmp' do
  self.rubyforge_name = 'net-snmp'
  self.author         = ['Brian Gugliemetti']
  self.email          = %w[briang@spiceworks.com]
  self.version        = "0.2.0"
  self.need_tar       = false
  self.need_zip       = false
  
  spec_extras[:required_ruby_version] = Gem::Requirement.new('>= 1.8.6')
  spec_extras[:extensions] = FileList["ext/**/extconf.rb"].to_a
end

file "#{HOE.spec.name}.gemspec" => ['Rakefile', 'tasks/gem.rake'] do |t|
  puts "Generating #{t.name}"
  File.open(t.name, 'w') { |f| f.puts HOE.spec.to_yaml }
end

desc "Generate or update the standalone gemspec file for the project"
task :gemspec => ["#{HOE.spec.name}.gemspec"]
