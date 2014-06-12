require 'rspec'
require 'yaml'
require 'nexpose_ticketing/helpers/servicenow_helper'

describe 'ServiceNow Helper ticketing' do

  before(:each) do
    @helper = ServiceNowHelper.new(nil, nil)
    @helper.log = NexposeTicketing::NXLogger.new
  end

  it 'create a ticket by default' do
    dummy_tickets = IO.readlines('servicenow_dummy_two_default_tickets.txt')
    dummy_tickets.map! { |x| x.chomp }
    @helper.servicenow_data = { servicenow_url: 'https://dummy', username: 'dummy', password: 'dummy' }
    tickets = @helper.prepare_tickets_default(IO.read('../two_vulns_report.csv'))
    expect(tickets).to eq dummy_tickets
  end

  it 'create a ticket by IP' do
    dummy_tickets = IO.readlines('servicenow_dummy_one_ip_ticket.txt')
    dummy_tickets.map! { |x| x.chomp }
    @helper.servicenow_data = { servicenow_url: 'https://dummy', username: 'dummy', password: 'dummy' }
    tickets = @helper.prepare_tickets_by_ip(IO.read('../two_vulns_report.csv'))
    expect(tickets).to eq dummy_tickets
  end
end
