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
  # as a separate HTTP post).
  #
  # * *Args*    :
  #   - +tickets+ -  List of JSON-formatted ticket creates (new tickets).
  #
  def create_tickets(tickets)
    fail 'Ticket(s) cannot be empty' if tickets.nil? || tickets.empty?

    tickets.each do |ticket|
      send_ticket(ticket, @servicenow_data[:servicenow_url], @servicenow_data[:redirect_limit])
    end
  end

  # Sends ticket updates (in JSON format) to ServiceNow individually (each ticket in the list as a 
  # separate HTTP post).
  #
  # * *Args*    :
  #   - +tickets+ -  List of JSON-formatted ticket updates.
  #
  def update_tickets(tickets)
    if tickets.nil? || tickets.empty?
      @log.log_message("No tickets to update.")
    else
      tickets.each do |ticket|
        send_ticket(ticket, @servicenow_data[:servicenow_url], @servicenow_data[:redirect_limit])
      end
    end
  end
  
  # Sends ticket closure (in JSON format) to ServiceNow individually (each ticket in the list as a 
  # separate HTTP post).
  #
  # * *Args*    :
  #   - +tickets+ -  List of JSON-formatted ticket closures.
  #
  def close_tickets(tickets)
    if tickets.nil? || tickets.empty?
      @log.log_message("No tickets to close.")
    else
      tickets.each do |ticket|
        send_ticket(ticket, @servicenow_data[:servicenow_url], @servicenow_data[:redirect_limit])
      end
    end
  end

  # Post an individual JSON-formatted ticket to ServiceNow. If the response from the post is a 301/
  # 302 redirect, the method will attempt to resend the ticket to the response's location for up to
  # [limit] times (which starts at the redirect_limit config value and is decremented with each 
  # redirect response.
  #
  # * *Args*    :
  #   - +ticket+ -  JSON-formatted ticket.
  #   - +url+ -     URL to post the ticket to.
  #   - +limit+ -   The amount of times to retry the send ticket request before failing.l
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
    # Setting verbose_mode to 'Y' will debug the https call(s).
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
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of JSON-formated tickets for creating within ServiceNow.
  #
  def prepare_create_tickets(vulnerability_list)
    @ticket = Hash.new(-1)
    case @options[:ticket_mode]
    # 'D' Default mode: IP *-* Vulnerability
    when 'D'
      prepare_create_tickets_default(vulnerability_list)
    # 'I' IP address mode: IP address -* Vulnerability
    when 'I'
      prepare_create_tickets_by_ip(vulnerability_list)
    else
      fail 'No ticketing mode selected.'
    end
  end
  
  # Prepares a list of vulnerabilities into a list of JSON-formatted tickets (incidents) for 
  # ServiceNow. The preparation by default means that each vulnerability within Nexpose is a 
  # separate incident within ServiceNow.  This makes for smaller, more actionalble incidents but 
  # could lead to a very large total number of incidents.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of JSON-formated tickets for creating within ServiceNow.
  #
  def prepare_create_tickets_default(vulnerability_list)
    @log.log_message("Preparing tickets by default method.")
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      # ServiceNow doesn't allow new line characters in the incident short description.
      summary = row['summary'].gsub(/\n/, ' ')

      @log.log_message("Creating ticket with IP address: #{row['ip_address']} and summary: #{summary}")
      # NXID in the work_notes is a unique identifier used to query incidents to update/resolve 
      # incidents as they are resolved in Nexpose.
      ticket = {
          'sysparm_action' => 'insert',
          'caller_id' => "#{@servicenow_data[:username]}",
          'category' => 'Software',
          'impact' => '1',
          'urgency' => '1',
          'short_description' => "#{row['ip_address']} => #{summary}",
          'work_notes' => "Summary: #{summary}
                          Fix: #{row['fix']} 
                          ----------------------------------------------------------------------------
                          URL: #{row['url']}
                          NXID: #{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}"
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
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of JSON-formated tickets for creating within ServiceNow.
  #
  def prepare_create_tickets_by_ip(vulnerability_list)
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
          'work_notes' => "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++
                           ++ New Vulnerabilities +++++++++++++++++++++++++++++++++++++
                           +++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
        }
      end
      if current_ip == row['ip_address']
        @ticket['work_notes'] += 
          "==========================================
          Summary: #{row['summary']}
          ----------------------------------------------------------------------------
          Fix: #{row['fix']}"
        unless row['url'].nil?
          @ticket['work_notes'] += 
            "----------------------------------------------------------------------------
             URL: #{row['url']}"
        end
      end
      unless current_ip == row['ip_address']
        # NXID in the work_notes is the unique identifier used to query incidents to update them.
        @ticket['work_notes'] += "\nNXID: #{current_ip}"
        @ticket = @ticket.to_json
        tickets.push(@ticket)
        current_ip = -1
        redo
      end
    end
    # NXID in the work_notes is the unique identifier used to query incidents to update them.
    @ticket['work_notes'] += "\nNXID: #{current_ip}"
    tickets.push(@ticket.to_json) unless @ticket.nil?
    tickets
  end
  
  # Prepare ticket updates from the CSV of vulnerabilities exported from Nexpose. This method 
  # currently only supports updating IP-address mode tickets in ServiceNow. The list of vulnerabilities 
  # are ordered by IP address and then by ticket_status, allowing the method to loop through and  
  # display new, old, and same vulnerabilities in that order.
  #
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of JSON-formated tickets for updating within ServiceNow.
  #
  def prepare_update_tickets(vulnerability_list)
    fail 'Ticket updates are only supported in IP-address mode.' if @options[:ticket_mode] == 'D'
    @ticket = Hash.new(-1)
    
    @log.log_message("Preparing ticket updates by IP address.")
    tickets = []
    current_ip = -1
    ticket_status = 'New'
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      if current_ip == -1 
        current_ip = row['ip_address']
        ticket_status = row['comparison']
        @log.log_message("Creating ticket update with IP address: #{row['ip_address']}")
        @log.log_message("Ticket status #{ticket_status}")
        @ticket = {
          'sysparm_action' => 'update',
          'sysparm_query' => "work_notesCONTAINSNXID: #{row['ip_address']}",
          'work_notes' => 
            "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++
             ++ #{row['comparison']} Vulnerabilities +++++++++++++++++++++++++++++++++++++
             +++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
        }
      end
      if current_ip == row['ip_address']
        # If the ticket_status is different, add a a new 'header' to signify a new block of tickets.
        unless ticket_status == row['comparison']
          @ticket['work_notes'] += 
            "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++
             ++ #{row['comparison']} Vulnerabilities +++++++++++++++++++++++++++++++++++++
             +++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
          ticket_status = row['comparison']
        end
        
        @ticket['work_notes'] += 
          "\n\n==========================================
           Summary: #{row['summary']}
           ----------------------------------------------------------------------------
           Fix: #{row['fix']}"
        # Only add the URL block if data exists in the row.
        unless row['url'].nil?
          @ticket['work_notes'] += 
            "----------------------------------------------------------------------------
             URL: #{row['url']}"
        end
      end
      unless current_ip == row['ip_address']
        # NXID in the work_notes is the unique identifier used to query incidents to update them.
        @ticket['work_notes'] += "\nNXID: #{current_ip}"
        @ticket = @ticket.to_json
        tickets.push(@ticket)
        current_ip = -1
        redo
      end
    end
    # NXID in the work_notes is the unique identifier used to query incidents to update them.
    @ticket['work_notes'] += "\nNXID: #{current_ip}"
    tickets.push(@ticket.to_json) unless @ticket.nil?
    tickets
  end
  
  # Prepare ticket closures from the CSV of vulnerabilities exported from Nexpose. This method 
  # currently only supports updating default mode tickets in ServiceNow.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of JSON-formated tickets for closing within ServiceNow.
  #
  def prepare_close_tickets(vulnerability_list)
    fail 'Ticket closures are only supported in default mode.' if @options[:ticket_mode] == 'I'
    @log.log_message("Preparing ticket closures by default method.")
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      # 'state' 7 is the "Closed" state within ServiceNow.
      ticket = {
          'sysparm_action' => 'update',
          'sysparm_query' => "work_notesCONTAINSNXID: #{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}",
          'state' => '7'
      }.to_json
      tickets.push(ticket)
    end
    tickets
  end
end
