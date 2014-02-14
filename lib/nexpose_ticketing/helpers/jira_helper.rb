require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'csv'
# This class serves as the JIRA interface
# that creates issues within JIRA from vulnerabilities
# found in Nexpose.
# Copyright:: Copyright (c) 2014 Rapid7, LLC.
class JiraHelper
  attr_accessor :jira_data, :options
  def initialize(jira_data, options)
    @jira_data = jira_data
    @options = options
  end

  def create_ticket(tickets)
    fail 'Ticket(s) cannot be empty.' if tickets.empty? || tickets.nil?
    tickets.each do |ticket|
      headers = { 'Content-Type' => 'application/json',
                  'Accept' => 'application/json' }
      url = URI.parse("#{@jira_data[:jira_url]}")
      req = Net::HTTP::Post.new(@jira_data[:jira_url], headers)
      req.basic_auth @jira_data[:username], @jira_data[:password]
      req.body = ticket
      resp = Net::HTTP.new(url.host, url.port)
      # Enable this line for debugging the https call.
      # resp.set_debug_output $stderr
      resp.use_ssl = true if @jira_data[:jira_url].to_s.start_with?('https')
      resp.verify_mode = OpenSSL::SSL::VERIFY_NONE
      resp.start { |http| http.request(req) }
    end
  end

  # Prepares tickets from the CSV.
  def prepare_tickets(vulnerability_list)
    @ticket = Hash.new(-1)
    case @options[:ticket_mode]
    # 'D' Default IP *-* Vulnerability
    when 'D'
      prepare_tickets_default(vulnerability_list)
    # 'I' IP address -* Vulnerability
    when 'I'
      prepare_tickets_by_ip(vulnerability_list)
    else
        fail 'No ticketing mode selected.'
    end
  end

  # Prepares and creates tickets in default mode.
  def prepare_tickets_default(vulnerability_list)
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      # JiraHelper doesn't like new line characters in their summaries.
      summary = row['summary'].gsub(/\n/, ' ')
      ticket = {
          'fields' => {
              'project' => {
                  'key' => "#{@jira_data[:project]}" },
              'summary' => "#{row['ip_address']} => #{summary}",
              'description' => "#{row['fix']} \n\n #{row['url']}",
              'issuetype' => {
                  'name' => 'Task' }
          }
      }.to_json
      tickets.push(ticket)
    end
    tickets
  end

  # Prepares and creates tickets in IP mode.
  def prepare_tickets_by_ip(vulnerability_list)
    tickets = []
    current_ip = -1
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      if current_ip == -1
        current_ip = row['ip_address']
        @ticket = {
            'fields' => {
                'project' => {
                    'key' => "#{@jira_data[:project]}" },
                'summary' => "#{row['ip_address']} => Vulnerabilities",
                'description' => '',
                'issuetype' => {
                    'name' => 'Task' }
            }
        }
      end
      if current_ip == row['ip_address']
        @ticket['fields']['description'] += "\n ==============================\n
          #{row['summary']} \n ==============================\n
          \n #{row['fix']}\n\n #{row['url']}"
      end
      unless current_ip == row['ip_address']
        @ticket = @ticket.to_json
        tickets.push(@ticket)
        current_ip = -1
        redo
      end
    end
    tickets.push(@ticket.to_json) unless @ticket.nil?
    tickets
  end
end
