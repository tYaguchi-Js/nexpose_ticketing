require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'csv'
require 'nexpose_ticketing/nx_logger'
require 'nexpose_ticketing/version'
require 'nexpose_ticketing/common_helper'
require 'securerandom'

# Serves as the ServiceNow interface for creating/updating issues from 
# vulnelrabilities found in Nexpose.
class ServiceNowHelper
  attr_accessor :servicenow_data, :options, :log, :transform
  def initialize(servicenow_data, options)
    @servicenow_data = servicenow_data
    @options = options
    @log = NexposeTicketing::NxLogger.instance
    @common_helper = NexposeTicketing::CommonHelper.new(@options)
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
      @log.log_message('No tickets to update.')
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
      @log.log_message('No tickets to close.')
    else
      tickets.each do |ticket|
        send_ticket(ticket, @servicenow_data[:servicenow_url], @servicenow_data[:redirect_limit])
      end
    end
  end

  # Retrieves the unique ticket identifier for a particular NXID if one exists.
  #
  # * *Args*    :
  #   - +nxid+ - NXID of the ticket to be updated.
  #
  def get_ticket_identifier(nxid)
    headers = { 'Content-Type' => 'application/json',
                'Accept' => 'application/json' }
 
    #Get the address
    query = "incident.do?JSONv2&sysparm_query=active=true^u_nxid=#{nxid}"
    uri = URI.join(@servicenow_data[:servicenow_url], '/')
    full_url = URI.join(uri, "/").to_s + query
    req = Net::HTTP::Get.new(full_url, headers)
    req.basic_auth @servicenow_data[:username], @servicenow_data[:password]
    resp = Net::HTTP.new(uri.host, uri.port)

    # Enable this line for debugging the https call.
    # resp.set_debug_output(@log)

    if uri.scheme == 'https'
      resp.use_ssl = true 
      resp.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    
    begin
      response = resp.request(req)
    rescue Exception => e
      @log.log_error_message("Request failed for NXID #{nxid}.\n#{e}")
    end

    tickets = JSON.parse(response.body)
    records = tickets['records']
    if records.count > 1
      @log.log_error_message("Found more than one result for NXID #{nxid}. Updating first result.")
      records.each { |r| @log.log_error_message("NXID #{nxid} found with Rapid7 Identifier #{r['u_rpd_id']}") }
    elsif records.count == 0
      @log.log_error_message("No results found for NXID #{nxid}.")
      return nil
    end

    ticket_id = records.first['u_rpd_id']
    @log.log_message("Found ticket for NXID #{nxid} ID is: #{ticket_id}")
    if ticket_id.nil?
      @log.log_error_message("ID is nil for ticket with NXID #{nxid}.")
    end

    ticket_id
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
      raise ArgumentError, res['error']
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
  def prepare_create_tickets(vulnerability_list, nexpose_identifier_id)
    @log.log_message('Preparing ticket requests...')
    case @options[:ticket_mode]
    # 'D' Default IP *-* Vulnerability
    when 'D' then matching_fields = ['ip_address', 'vulnerability_id']
    # 'I' IP address -* Vulnerability
    when 'I' then matching_fields = ['ip_address']
    # 'V' Vulnerability -* Assets
    when 'V' then matching_fields = ['vulnerability_id']
    else
        fail 'Unsupported ticketing mode selected.'
    end

    prepare_tickets(vulnerability_list, nexpose_identifier_id, matching_fields)
  end

  # Prepares a list of vulnerabilities into a list of JSON-formatted tickets (incidents) for 
  # ServiceNow.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of JSON-formated tickets for creating within ServiceNow.
  #
  def prepare_tickets(vulnerability_list, nexpose_identifier_id, matching_fields)
    @ticket = Hash.new(-1)
    
    @log.log_message("Preparing tickets in #{options[:ticket_mode]} address.")
    tickets = []
    previous_row = nil
    description = nil
    action = 'insert' 
    
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      if previous_row.nil?
        previous_row = row.dup
        nxid = @common_helper.generate_nxid(nexpose_identifier_id, row)

        action = unless row['comparison'].nil? || row['comparison'] == 'New'
                   'update'
                 else
                   'insert'
                 end

        @ticket = {
          'sysparm_action' => action,
          'caller_id' => "#{@servicenow_data[:username]}",
          'category' => 'Software',
          'impact' => '1',
          'urgency' => '1',
          'short_description' => @common_helper.get_title(row),
          'work_notes' => "",
          'u_nxid' => nxid,
          'u_rpd_id' => nil
        }
        description = @common_helper.get_description(nexpose_identifier_id, row)
      elsif matching_fields.any? { |x|  previous_row[x].nil? || previous_row[x] != row[x] }
        info = @common_helper.get_field_info(matching_fields, previous_row)
        @log.log_message("Generated ticket with #{info}")

        @ticket['work_notes'] = @common_helper.print_description(description)
        tickets.push(@ticket)
        
        previous_row = nil
        description = nil
        redo
      else
        @ticket['sysparm_action'] = 'update' unless row['comparison'] == 'New'
        description = @common_helper.update_description(description, row)      
      end
    end

    unless @ticket.nil? || @ticket.empty?
      @ticket['work_notes'] = @common_helper.print_description(description) unless (@ticket.size == 0)
      tickets.push(@ticket)
    end
    @log.log_message("Generated <#{tickets.count.to_s}> tickets.")

    tickets.map do |t|
      if t['sysparm_action'] == 'update'
        t['sysparm_action'] = 'insert'
        t['u_rpd_id'] = get_ticket_identifier(t['u_nxid'])
      end

      t['u_rpd_id'] ||= SecureRandom.uuid
      t.to_json
    end
  end

  # Prepare ticket updates from the CSV of vulnerabilities exported from Nexpose. The list of vulnerabilities 
  # are ordered depending on the ticketing mode and then by ticket_status, allowing the method to loop through and  
  # display new, old, and same vulnerabilities in that order.
  #
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of JSON-formated tickets for updating within ServiceNow.
  #
  def prepare_update_tickets(vulnerability_list, nexpose_identifier_id)
    
    case @options[:ticket_mode]
    when 'D' then fail 'Ticket updates are not supported in Default mode.'
    # 'I' IP address -* Vulnerability
    when 'I' then matching_fields = ['ip_address']
    # 'V' Vulnerability -* Assets
    when 'V' then matching_fields = ['vulnerability_id']
    else
        fail 'Unsupported ticketing mode selected.'
    end

    prepare_tickets(vulnerability_list, nexpose_identifier_id, matching_fields)
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
  def prepare_close_tickets(vulnerability_list, nexpose_identifier_id)
    @log.log_message("Preparing ticket closures for mode #{@options[:ticket_mode]}.")
    tickets = []
    @nxid = nil
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      @nxid = @common_helper.generate_nxid(nexpose_identifier_id, row)
      # 'state' 7 is the "Closed" state within ServiceNow.
      ticket_id = get_ticket_identifier(@nxid)
      @log.log_message("Closing ticket with NXID: #{@nxid}.")
      ticket = {
          'sysparm_action' => 'insert',
          'u_rpd_id' => ticket_id,
          'state' => '7'
      }.to_json
      tickets.push(ticket)
    end
    tickets
  end
end