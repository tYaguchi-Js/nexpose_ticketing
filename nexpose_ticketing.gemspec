# encoding: utf-8

Gem::Specification.new do |s|
  s.name                  = 'nexpose_ticketing'
  s.version               = '0.8.2'
  s.homepage              = 'https://github.com/rapid7/nexpose_ticketing'
  s.summary               = 'Ruby Nexpose Ticketing Engine.'
  s.description           = 'This gem provides a Ruby implementation of different integrations with ticketing services for Nexpose.'
  s.license               = 'BSD'
  s.authors               = ['Damian Finol'], ['JJ Cassidy']
  s.email                 = ['integrations_support@rapid7.com']
  s.files                 = Dir['[A-Z]*'] + Dir['lib/**/*'] + Dir['tests/**']
  s.files.reject!          { |fn| fn.include? ".gem" }
  s.require_paths         = ['lib']
  s.extra_rdoc_files      = ['README.md']
  s.required_ruby_version = '>= 1.9'
  s.platform              = 'ruby'
  s.executables           = ['nexpose_jira','nexpose_servicenow','nexpose_remedy', 'nexpose_servicedesk']
  s.add_runtime_dependency 'nexpose', '~> 0.8.0'
  s.add_runtime_dependency 'savon', '~> 2.1'
  s.add_runtime_dependency 'nokogiri', '~> 1.6'
  s.add_development_dependency 'rspec', '~> 3.2', '>= 3.2.0'
  s.add_development_dependency 'rspec-mocks', '~> 3.2', '>= 3.2.0'
end
