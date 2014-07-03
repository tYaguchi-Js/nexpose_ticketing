require 'rspec'
require 'yaml'
require 'spec_helper'
require 'savon/mock/spec_helper'
require 'nexpose_ticketing/helpers/remedy_helper'

describe 'Remedy Helper ticketing' do

  before(:each) do
    @helper = RemedyHelper.new(nil, nil)
    @helper.log = NexposeTicketing::NXLogger.new
    savon.mock!
  end
  
  after(:each) do
    savon.unmock!
  end

  it 'create a ticket by default' do
    dummy_tickets = IO.readlines('remedy_dummy_two_default_tickets.txt')
    dummy_tickets.map! { |x| x.chomp }
    @helper.remedy_data = { create_soap_endpoint: 'https://dummy', query_modify_soap_endpoint: 'https://dummy', 
      username: 'test', password: 'testpassword', first_name: 'test', last_name: 'test', open_timeout: 30, read_timeout: 30 }
    tickets = @helper.prepare_create_tickets_default(IO.read('../two_vulns_report.csv'))
    expect(tickets).to eq dummy_tickets
  end

  it 'create a ticket by IP' do
    dummy_tickets = IO.readlines('remedy_dummy_one_ip_ticket.txt')
    dummy_tickets.map! { |x| x.chomp }
    @helper.remedy_data = { create_soap_endpoint: 'https://dummy', query_modify_soap_endpoint: 'https://dummy', 
      username: 'test', password: 'testpassword', first_name: 'test', last_name: 'test', open_timeout: 30, read_timeout: 30 }
    tickets = @helper.prepare_create_tickets_by_ip(IO.read('../two_vulns_report.csv'))
    expect(tickets).to eq dummy_tickets
  end
  
  it 'close a ticket' do
    dummy_tickets = IO.readlines('remedy_dummy_two_default_closures.txt')
    dummy_tickets.map! { |x| x.chomp }
    @helper.remedy_data = { create_soap_endpoint: 'https://dummy', query_modify_soap_endpoint: 'https://dummy', 
      username: 'test', password: 'testpassword', first_name: 'test', last_name: 'test', open_timeout: 30, read_timeout: 30 }
    @helper.options = { ticket_mode: 'D' }
    tickets = @helper.prepare_close_tickets(IO.read('../two_vulns_report.csv'))
    expect(tickets).to eq dummy_tickets
  end
  
  it 'close a ticket when in I-mode' do
    dummy_tickets = IO.readlines('remedy_dummy_two_default_closures.txt')
    dummy_tickets.map! { |x| x.chomp }
    @helper.remedy_data = { create_soap_endpoint: 'https://dummy', query_modify_soap_endpoint: 'https://dummy', 
      username: 'test', password: 'testpassword', first_name: 'test', last_name: 'test', open_timeout: 30, read_timeout: 30 }
    @helper.options = { ticket_mode: 'I' }
    expect{@helper.prepare_close_tickets(IO.read('../two_vulns_report.csv'))}.to raise_error(StandardError, 'Ticket closures are only supported in default mode.')
  end
  
  it 'update a ticket by IP' do
    dummy_tickets = IO.readlines('remedy_dummy_one_ip_update.txt')
    dummy_tickets.map! { |x| x.chomp }
    @helper.remedy_data = { create_soap_endpoint: 'https://dummy', query_modify_soap_endpoint: 'https://dummy', 
      username: 'test', password: 'testpassword', first_name: 'test', last_name: 'test', open_timeout: 30, read_timeout: 30 }
    @helper.options = { ticket_mode: 'I' }
    tickets = @helper.prepare_update_tickets(IO.read('../two_vulns_report_update.csv'))
    expect(tickets).to eq dummy_tickets
  end
  
  it 'update a ticket by IP when in D-mode' do
    dummy_tickets = IO.readlines('remedy_dummy_one_ip_update.txt')
    dummy_tickets.map! { |x| x.chomp }
    @helper.remedy_data = { create_soap_endpoint: 'https://dummy', query_modify_soap_endpoint: 'https://dummy', 
      username: 'test', password: 'testpassword', first_name: 'test', last_name: 'test', open_timeout: 30, read_timeout: 30 }
    @helper.options = { ticket_mode: 'D' }
    expect{@helper.prepare_update_tickets(IO.read('../two_vulns_report_update.csv'))}.to raise_error(StandardError, 'Ticket updates are only supported in IP-address mode.')
  end
end
