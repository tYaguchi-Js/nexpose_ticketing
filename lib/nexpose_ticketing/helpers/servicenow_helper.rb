require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'csv'
require 'nexpose_ticketing/nx_logger'
require 'nexpose_ticketing/version'
require_relative './base_helper'
require 'securerandom'
require 'typhoeus'

# Serves as the ServiceNow interface for creating/updating issues from 
# vulnerabilities found in Nexpose.
class ServiceNowHelper < BaseHelper

  NEW_STATE = 1
  RESOLVED_STATE = 6
  CLOSED_STATE = 7

  attr_accessor :log, :transform
  def initialize(service_data, options, mode)
    super(service_data, options, mode)
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
  def prepare_tickets(vulnerability_list, nexpose_identifier_id)
    @metrics.start
    matching_fields = @mode_helper.get_matching_fields
    @ticket = Hash.new(-1)

    @log.log_message("Preparing tickets in #{options[:ticket_mode]} mode format.")
    tickets = []
    previous_row = nil
    description = nil
    action = 'insert'

    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      if previous_row.nil?
        previous_row = row.dup
        nxid = @mode_helper.get_nxid(nexpose_identifier_id, row)

        action = if row['comparison'].nil? || row['comparison'] == 'New'
                   'insert'
                 else
                   'update'
                 end

        @ticket = {
          'sysparm_action' => action,
          'u_caller_id' => "#{@service_data[:username]}",
          'u_category' => 'Software',
          'u_impact' => '1',
          'u_urgency' => '1',
          'u_short_description' => @mode_helper.get_title(row),
          'u_work_notes' => "",
          'u_nxid' => nxid,
          'u_rpd_id' => nil
        }
        description = @mode_helper.get_description(nexpose_identifier_id, row)
      elsif matching_fields.any? { |x|  previous_row[x].nil? || previous_row[x] != row[x] }
        info = @mode_helper.get_field_info(matching_fields, previous_row)
        @log.log_message("Generated ticket with #{info}")

        @ticket['u_work_notes'] = @mode_helper.print_description(description)
        tickets.push(@ticket)

        previous_row = nil
        description = nil
        redo
      else
        unless row['comparison'].nil? || row['comparison'] == 'New'
          @ticket['sysparm_action'] = 'update'
        end
        description = @mode_helper.update_description(description, row)
      end
    end

    unless @ticket.nil? || @ticket.empty?
      info = @mode_helper.get_field_info(matching_fields, previous_row)
      @log.log_message("Generated ticket with #{info}")
      @ticket['u_work_notes'] = @mode_helper.print_description(description) unless (@ticket.size == 0)
      tickets.push(@ticket)
    end
    @log.log_message("Generated <#{tickets.count.to_s}> tickets.")

    tickets
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
    prepare_tickets(vulnerability_list, nexpose_identifier_id)
  end

  # Sends a list of tickets (in JSON format) to ServiceNow individually (each ticket in the list
  # as a separate HTTP post).
  #
  # * *Args*    :
  #   - +tickets+ -  List of JSON-formatted ticket creates (new tickets).
  #
  def create_tickets(tickets)
    fail 'Ticket(s) cannot be empty' if tickets.nil? || tickets.empty?
    final_ticket = tickets.count - 1
    ticket_index = 0

    hydra = Typhoeus::Hydra.new
    requests = tickets.map do |ticket|
      ticket['u_rpd_id'] = SecureRandom.uuid
      request = generate_post_request(ticket.to_json,
                                      ticket_index == final_ticket)
      hydra.queue request
      ticket_index += 1
      request
    end

    hydra.run

    @metrics.created tickets.count
    @log.log_message('Created ticket batch.')
    requests.map(&:response)
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
    prepare_tickets(vulnerability_list, nexpose_identifier_id)
  end

  # Sends ticket updates (in JSON format) to ServiceNow by placing each request
  # on a Typhoeus queue (each ticket in the list as a separate HTTP post).
  #
  # * *Args*    :
  #   - +tickets+ -  List of Hash-formatted ticket updates.
  #
  def update_tickets(tickets)
    if tickets.nil? || tickets.empty?
      @log.log_message('No tickets to update.')
      return
    end

    requests = []
    final_ticket = tickets.count - 1

    hydra = Typhoeus::Hydra.new
    tickets.each_with_index do |ticket, i|
      if ticket['sysparm_action'] == 'update'
        id_request = generate_identifier_request(ticket['u_nxid'])
        id_request.on_complete do |response|
          ticket['sysparm_action'] = 'insert'

          current_data = parse_identifier_response(response, ticket['u_nxid'])
          u_rpd_id = current_data[:id]
          ticket['u_rpd_id'] = u_rpd_id || SecureRandom.uuid

          if current_data[:state] == RESOLVED_STATE
            ticket['u_state'] = NEW_STATE
            title = "(Reopened) #{ticket['u_short_description']}"
            ticket['u_short_description'] = title
            current_notes = ticket['u_work_notes'].rpartition("\n\n\nNXID: ")
            new_notes = '++ Reopened by Nexpose Ticketing Gem ' \
                        "++\n#{current_notes.first}"
            nxid = current_notes[1,2].join('').lstrip
            description = @mode_helper.finalize_description(new_notes, nxid)
            ticket['u_work_notes'] = description
          end

          ticket_request = generate_post_request(ticket.to_json,
                                                 i == final_ticket)
          hydra.queue ticket_request
          ticket['u_rpd_id'] == u_rpd_id ? @metrics.updated : @metrics.created
          requests << ticket_request
        end

        hydra.queue id_request
      elsif ticket['sysparm_action'] == 'insert'
        ticket['u_rpd_id'] ||= SecureRandom.uuid
        ticket_request = generate_post_request(ticket.to_json,
                                               i == final_ticket)
        hydra.queue ticket_request
        @metrics.created
        requests << ticket_request
      end
    end

    hydra.run
    @log.log_message('Updated ticket batch.')
    requests.map(&:response)
  end



  #  Method generates a HTTP POST request containing the provided ticket to
  #  send to ServiceNow. Provides error handling via on_complete functionality
  #
  # * *Args*    :
  #   - +ticket+ -  The ticket to be sent to ServiceNow
  #   - +forbid_connection_reuse+ - Whether the current HTTP connection can be
  #                                 reused to send tickets to ServiceNow.
  #
  # * *Returns* :
  #   - A HTTP post request object to be placed on the queue for sending
  #
  def generate_post_request(ticket, forbid_connection_reuse)
    request = generate_ticket_request(ticket, forbid_connection_reuse)
    request.on_complete do |response|
      unless response.success?
        msg = if response.timed_out?
                'Time out has occurred.'
              elsif response.code == 0
                response.return_message
              else
                "HTTP request failed: #{response.code}"
              end

        @log.log_error_message msg
        raise msg
      end
    end
    request
  end

  #  Method generates a HTTP POST request containing the provided ticket to
  #  send to ServiceNow. Provides error handling via on_complete functionality
  #
  # * *Args*    :
  #   - +ticket+ -  The ticket to be sent to ServiceNow
  #   - +forbid_connection_reuse+ - Whether the current HTTP connection can be
  #                                 reused to send tickets to ServiceNow.
  #
  # * *Returns* :
  #   - A HTTP request object to be placed on the queue for sending
  #
  def generate_ticket_request(ticket, forbid_connection_reuse)
    address = @service_data[:servicenow_url]
    userpwd = "#{@service_data[:username]}:#{@service_data[:password]}"
    headers = { 'Content-Type' => 'application/json' }

    options = {
      method: :post,
      userpwd: userpwd,
      headers: headers,
      accept_encoding: 'application/json',
      maxredirs: @service_data[:redirect_limit],
      ssl_verifyhost: 0,
      forbid_reuse: forbid_connection_reuse,
      body: ticket
    }

    Typhoeus::Request.new(address, options)
  end

  def generate_identifier_request(nxid)
    query = "incident.do?JSONv2&sysparm_query=active=true^u_nxid=#{nxid}"
    url = URI.join(@service_data[:servicenow_url], "/").to_s + query
    userpwd = "#{@service_data[:username]}:#{@service_data[:password]}"
    headers = { 'Content-Type' => 'application/json' }
    options = {
      method: :get,
      userpwd: userpwd,
      headers: headers,
      accept_encoding: 'application/json',
      maxredirs: @service_data[:redirect_limit],
      ssl_verifyhost: 0
    }

    Typhoeus::Request.new(url, options)
  end

  def parse_identifier_response(response, nxid)
    tickets = JSON.parse(response.body)
    records = tickets['records']

    if records.count > 1
      @log.log_error_message("Found more than one result for NXID #{nxid}. " \
      'Updating first result.')
      records.each { |r| @log.log_error_message("NXID #{nxid} found with " \
      "Rapid7 Identifier #{r['u_rpd_id']}") }
    elsif records.count == 0
      @log.log_error_message("No results found for NXID #{nxid}.")
      return { id: nil, state: nil }
    end

    ticket_id = records.first['u_rpd_id']
    state = records.first['state']
    @log.log_message("Found ticket for NXID #{nxid} ID is: #{ticket_id}")
    if ticket_id.nil?
      @log.log_error_message("ID is nil for ticket with NXID #{nxid}.")
      state = nil
    end

    { id: ticket_id, state: state }
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
    requests = {}

    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      nxid = @mode_helper.get_nxid(nexpose_identifier_id, row)
      @log.log_message("Closing ticket with NXID: #{nxid}.")
      request = generate_identifier_request(nxid)
      requests[nxid] = request
    end

    requests
  end

  # Sends ticket closure (in JSON format) to ServiceNow individually
  # (each ticket in the list as a separate HTTP post).
  #
  # * *Args*    :
  #   - +requests+ -  Hash containing NXIDs and associated Typheous requests.
  #
  def close_tickets(nxid_requests)
    if nxid_requests.nil? || nxid_requests.empty?
      @log.log_message('No tickets to close.')
      return
    end

    ticket = {
      'sysparm_action' => 'insert',
      'u_rpd_id' => nil,
      'u_state' => CLOSED_STATE
    }

    requests = []
    final_ticket = nxid_requests.count - 1

    hydra = Typhoeus::Hydra.new
    nxid_requests.each_with_index do |(nxid, request), i|
      request.on_complete do |response|
        u_rpd_id = parse_identifier_response(response, nxid)[:id]
        ticket['u_rpd_id'] = u_rpd_id
        ticket_request = generate_post_request(ticket.to_json,
                                               i == final_ticket)
        hydra.queue ticket_request
        requests << ticket_request
      end
      hydra.queue request
    end

    hydra.run
    @metrics.closed requests.count
    @log.log_message('Closed ticket batch.')
    requests.map(&:response)
  end
end
