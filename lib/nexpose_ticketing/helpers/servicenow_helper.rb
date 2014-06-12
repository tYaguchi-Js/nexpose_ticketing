require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'csv'
require 'nexpose_ticketing/nx_logger'

# Serves as the ServiceNow interface for creating/updating issues from 
# vulnelrabilities found in Nexpose.
class ServiceNowHelper
  attr_accessor :servicenow_data, :options, :log
  def initialize(servicenow_data, options)
    @servicenow_data = servicenow_data
    @options = options
    @log = NexposeTicketing::NXLogger.new
  end

  # Sends a list of tickets (in JSON format) to ServiceNow individually (each ticket in the list 
  # as a separate HTTP post.
  #
  # @param [tickets] List of JSON-formatted tickets
  #
  def create_ticket(tickets)
    fail 'Ticket(s) cannot be empty' if tickets.empty? || tickets.nil?

    tickets.each do |ticket|
      send_ticket(ticket, @servicenow_data[:servicenow_url], @servicenow_data[:redirect_limit])
    end
  end

  # Post an individual JSON-formatted ticket to ServiceNow. If the response from the post is a 301/
  # 302 redirect, the method will attempt to resend the ticket to the response's location for up to
  # [limit] times (which starts at the redirect_limit config value and is decremented with each 
  # redirect response.
  #
  # @param [ticket] JSON-formatted ticket.
  # @param [url] URL to post the ticket to.
  # @param [limit] The amount of times to retry the send ticket request.
  # 
  def send_ticket(ticket, url, limit)
    raise ArgumentError, 'HTTP Redirect too deep' if limit == 0

    uri = URI.parse(url)
    headers = { 'Content-Type' => 'application/json',
                'Accept' => 'application/json' }
    req = Net::HTTP::Post.new(url, headers)
    req.basic_auth @servicenow_data[:username], @servicenow_data[:password]
    req.body = ticket

    resp = Net::HTTP.new(uri.host, uri.port)
    # Uncomment the below line to debug the https call
    resp.set_debug_output $stderr if @servicenow_data[:verbose_mode] == 'Y'
    resp.use_ssl = true if uri.scheme == 'https'
    # Currently, we do not verify SSL certificates (in case the local servicenow instance uses
    # and unsigned or expired certificate)
    resp.verify_mode = OpenSSL::SSL::VERIFY_NONE
    res = resp.start { |http| http.request(req) }
    case res
      when Net::HTTPSuccess then res
      when Net::HTTPRedirection then send_ticket(ticket, res['location'], limit - 1)
    else
      @log.log_message("Error in response: #{res['error']}")
      res['error']
    end
  end

  # Prepare tickets from the CSV of vulnerabilities exported from Nexpose. This method determines 
  # how to prepare the tickets (either by default or by IP address) based on config options.
  #
  # @param [vulnerability_list] CSV of vulnerabilities within Nexpose.
  # 
  def prepare_tickets(vulnerability_list)
    @ticket = Hash.new(-1)
    case @options[:ticket_mode]
    # 'D' Default mode: IP *-* Vulnerability
    when 'D'
      prepare_tickets_default(vulnerability_list)
    # 'I' IP address mode: IP address -* Vulnerability
    when 'I'
      prepare_tickets_by_ip(vulnerability_list)
    else
      fail 'No ticketing mode selected.'
    end
  end

  # Prepares a list of vulnerabilities into a list of JSON-formatted tickets (incidents) for 
  # ServiceNow. The preparation by default means that each vulnerability within Nexpose is a 
  # separate incident within ServiceNow.  This makes for smaller, more actionalble incidents but 
  # could lead to a very large total number of incidents.
  #
  # @param [vulnerability_list] CSV of vulnerabilities within Nexpose.
  #
  def prepare_tickets_default(vulnerability_list)
    @log.log_message("Preparing tickets by default method.")
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      # ServiceNow doesn't allow new line characters in the incident short description.
      summary = row['summary'].gsub(/\n/, ' ')

      @log.log_message("Creating ticket with IP address: #{row['ip_address']} and summary: #{summary}")
      ticket = {
          'sysparm_action' => 'insert',
          'caller_id' => "#{@servicenow_data[:username]}",
          'category' => 'Software',
          'impact' => '1',
          'urgency' => '1',
          'short_description' => "#{row['ip_address']} => #{summary}",
          'work_notes' => "#{row['fix']} \n\n #{row['url']}"
      }.to_json
      tickets.push(ticket)
    end
    tickets
  end

  # Prepares a list of vulnerabilities into a list of JSON-formatted tickets (incidents) for 
  # ServiceNow. The preparation by IP means that all vulnerabilities within Nexpose for one IP 
  # address are consolidated into a single ServiceNow incident. This reduces the number of incidents
  # within ServiceNow but greatly increases the size of the work notes.
  #
  # @param [vulnerability_list] CSV of vulnerabilities within Nexpose.
  #
  def prepare_tickets_by_ip(vulnerability_list)
    @log.log_message("Preparing tickets by IP address.")
    tickets = []
    current_ip = -1
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      if current_ip == -1 
        current_ip = row['ip_address']
        @log.log_message("Creating ticket with IP address: #{row['ip_address']}")
        @ticket = {
          'sysparm_action' => 'insert',
          'caller_id' => "#{@servicenow_data[:username]}",
          'category' => 'Software',
          'impact' => '1',
          'urgency' => '1',
          'short_description' => "#{row['ip_address']} => Vulnerabilities",
          'work_notes' => "\n"
        }
      end
      if current_ip == row['ip_address']
        @ticket['work_notes'] += 
          "=========================================
          Summary: #{row['summary']}
          ------------------------------------------
          Fix: #{row['fix']}
          ------------------------------------------
          URL: [code]<a target=_blank href=#{row['url']}>#{row['url']}</a>[/code]\n\n"
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
