# encoding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'nexpose_ticketing/version'

Gem::Specification.new do |s|
  s.name                  = 'nexpose_ticketing'
  s.version               = NexposeTicketing::VERSION
  s.homepage              = 'https://github.com/rapid7/nexpose_ticketing'
  s.summary               = 'Ruby Nexpose Ticketing Engine.'
  s.description           = 'This gem provides a Ruby implementation of different integrations with ticketing services for Nexpose.'
  s.license               = 'BSD'
  s.authors               = ['Damian Finol'], ['JJ Cassidy'], ['David Valente']
  s.email                 = ['integrations_support@rapid7.com']
  s.files                 = Dir['[A-Z]*'] + Dir['lib/**/*'] + Dir['tests/**']
  s.files.reject!          { |fn| fn.include? ".gem" }
  s.require_paths         = ['lib']
  s.extra_rdoc_files      = ['README.md']
  s.required_ruby_version = '>= 1.9'
  s.platform              = 'ruby'
  s.executables           = ['nexpose_jira','nexpose_servicenow','nexpose_remedy', 'nexpose_servicedesk']
  s.add_runtime_dependency 'nexpose', '~> 2.1', '>= 2.1.0'
  s.add_runtime_dependency 'savon', '~> 2.1'
  s.add_runtime_dependency 'nokogiri', '~> 1.6'
  s.add_development_dependency 'rspec', '~> 3.2', '>= 3.2.0'
  s.add_development_dependency 'rspec-mocks', '~> 3.2', '>= 3.2.0'
end
