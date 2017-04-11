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
  s.license               = 'Ruby'
  s.authors               = ['Damian Finol'], ['JJ Cassidy'], ['David Valente'], ['Adam Robinson']
  s.email                 = ['support@rapid7.com']
  s.files                 = Dir['[A-Z]*'] + Dir['lib/**/*'] + Dir['tests/**']
  s.files.reject!          { |fn| fn.include? ".gem" }
  s.require_paths         = ['lib']
  s.extra_rdoc_files      = ['README.md']
  s.required_ruby_version = '>= 2.1.5'
  s.platform              = 'ruby'
  s.executables           = ['nexpose_ticketing']
  s.add_runtime_dependency 'nexpose', '~> 5.3.1', '>= 3.1.0'
  s.add_runtime_dependency 'savon', '~> 2.1'
  s.add_runtime_dependency 'nokogiri', '~> 1.6'
  s.add_runtime_dependency 'typhoeus', '~> 1.1', '>= 1.1.2'
  s.add_development_dependency 'rspec', '~> 3.2', '>= 3.2.0'
  s.add_development_dependency 'rspec-mocks', '~> 3.2', '>= 3.2.0'
end
