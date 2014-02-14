require 'rspec'
require 'nexpose_ticketing/helpers/jira_helper'

describe 'Jira Helper ticketing' do

  before(:each) do
    @helper = JiraHelper.new(nil, nil)
  end

  it 'create a ticket by default' do
    dummy_tickets = IO.readlines('jira_dummy_two_default_tickets.txt')
    dummy_tickets.map! { |x| x.chomp }
    @helper.jira_data = { jira_url: 'https://dummy', username: 'dummy', password: 'dummy', project: 'dummy' }
    tickets = @helper.prepare_tickets_default(IO.read('../two_vulns_report.csv'))
    expect(tickets).to eq dummy_tickets
  end

  it 'create a ticket by IP' do
    dummy_tickets = IO.readlines('jira_dummy_one_ip_ticket.txt')
    dummy_tickets.map! { |x| x.chomp }
    @helper.jira_data = { jira_url: 'https://dummy', username: 'dummy', password: 'dummy', project: 'dummy' }
    tickets = @helper.prepare_tickets_by_ip(IO.read('../two_vulns_report.csv'))
    expect(tickets).to eq dummy_tickets
  end
end
