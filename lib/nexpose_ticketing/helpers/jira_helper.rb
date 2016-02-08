require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'csv'
require 'nexpose_ticketing/nx_logger'
require 'nexpose_ticketing/version'
require 'nexpose_ticketing/common_helper'

# This class serves as the JIRA interface
# that creates issues within JIRA from vulnerabilities
# found in Nexpose.
# Copyright:: Copyright (c) 2014 Rapid7, LLC.
class JiraHelper
  attr_accessor :jira_data, :options
  def initialize(jira_data, options)
    @jira_data = jira_data
    @options = options
    @log = NexposeTicketing::NxLogger.instance

    @common_helper = NexposeTicketing::CommonHelper.new(@options)
  end

  # Fetches the Jira ticket key e.g INT-1. This is required to post updates to the Jira.
  #
  # * *Args*    :
  #   - +JQL query string+ -  Jira's Query Language string used to search for a ticket key.
  #
  # * *Returns* :
  #   - Jira ticket key if found, nil otherwise.
  #
  def get_jira_key(jql_query)
    fail 'JQL query string cannot be empty.' if jql_query.empty?
    headers = { 'Content-Type' => 'application/json',
                'Accept' => 'application/json' }

    uri = URI.parse(("#{@jira_data[:jira_url]}".split("/")[0..-2].join('/') + '/search'))
    uri.query = [uri.query, URI.escape(jql_query)].compact.join('&')
    req = Net::HTTP::Get.new(uri.to_s, headers)
    response = send_jira_request(uri, req)

    issues = JSON.parse(response.body)['issues']
   if issues.nil? || !issues.any? || issues.size > 1
     # If Jira returns more than one key for a "unique" NXID query result then something has gone wrong...
     # Safest response is to return no key and let logic elsewhere dictate the action to take.
     @log.log_message("Jira returned no key or too many keys for query result! Response was <#{issues}>")
     return nil
   end
   return issues[0]['key']
  end

  # Sends a HTTP request to the JIRA console. 
  #
  # * *Args*    :
  #   - +uri+ - Address of the JIRA endpoint.
  #   - +request+ - Request containing the query or ticket object. 
  #
  # * *Returns* :
  #   - HTTPResponse containing result from the JIRA console.
  #
  def send_request(uri, request, ticket=false)
    request.basic_auth @jira_data[:username], @jira_data[:password]
    resp = Net::HTTP.new(uri.host, uri.port)

    # Enable this line for debugging the https call.
    # resp.set_debug_output(@log)

    resp.use_ssl = uri.scheme == 'https'
    resp.verify_mode = OpenSSL::SSL::VERIFY_NONE

    return resp.request(request) unless ticket

    resp.start do |http|
      res = http.request(request)
      next if res.code.to_i.between?(200,299)
      @log.log_error_message("Error submitting ticket data: #{res.message}, #{res.body}")
      res
    end
  end

  # Sends a request to the JIRA console. 
  #
  # * *Args*    :
  #   - +uri+ - Address of the JIRA endpoint.
  #   - +request+ - Request containing the query. 
  #
  # * *Returns* :
  #   - HTTPResponse containing result from the JIRA console.
  #
  def send_jira_request(uri, request)
    send_request(uri, request)
  end

  # Sends a ticket object to the JIRA console. 
  #
  # * *Args*    :
  #   - +uri+ - Address of the JIRA endpoint.
  #   - +request+ - Request containing the ticket object. 
  #
  # * *Returns* :
  #   - HTTPResponse containing result from the JIRA console.
  #
  def send_ticket(uri, request)
    send_request(uri, request, true)
  end

  # Fetches the Jira ticket transition details for the given Jira ticket key. Tries to match the response to the
  # the desired transition in the configuration file.
  #
  # * *Args*    :
  #   - +Jira key+ -  Jira ticket key e.g. INT-1.
  #   - +Step ID+ -  Jira transition step id (Jira number assigned to a status).
  #
  # * *Returns* :
  #   - Jira transition details in JSON format if matched, nil otherwise.
  #
  def get_jira_transition_details(jira_key, step_id)
    fail 'Jira ticket key and transition step ID required to find transition details.' if jira_key.nil? || step_id.nil?

    headers = { 'Content-Type' => 'application/json',
                'Accept' => 'application/json' }

    uri = URI.parse(("#{@jira_data[:jira_url]}#{jira_key}/transitions?expand=transitions.fields."))
    req = Net::HTTP::Get.new(uri.to_s, headers)
    response = send_jira_request(uri, req)

    transitions = JSON.parse(response.body)

    if transitions.has_key? 'transitions'
      transitions['transitions'].each do |transition|
        if transition['to']['id'] == step_id.to_s
          return transition
        end
      end
    end
    error = "Response was <#{transitions}> and desired close Step ID was <#{@jira_data[:close_step_id]}>. Jira returned no valid transition to close the ticket!"
    @log.log_message(error)
    return nil
  end

  def create_tickets(tickets)
    fail 'Ticket(s) cannot be empty.' if tickets.nil? || tickets.empty?
    tickets.each do |ticket|
      headers = { 'Content-Type' => 'application/json',
                  'Accept' => 'application/json' }

      uri = URI.parse("#{@jira_data[:jira_url]}")
      req = Net::HTTP::Post.new(@jira_data[:jira_url], headers)
      req.body = ticket
      send_ticket(uri, req)
    end
  end

  # Prepares tickets from the CSV.
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

  def prepare_tickets(vulnerability_list, nexpose_identifier_id, matching_fields)
    @ticket = Hash.new(-1)

    @log.log_message("Preparing tickets for #{@options[:ticket_mode]} mode.")
    tickets = []
    previous_row = nil
    description = nil
    CSV.parse(vulnerability_list.chomp, headers: :first_row) do |row|
      if previous_row.nil?
        previous_row = row

        @ticket = {
            'fields' => {
                'project' => {
                    'key' => "#{@jira_data[:project]}" },
                'summary' => @common_helper.get_title(row),
                'description' => '',
                'issuetype' => {
                    'name' => 'Task' }
            }
        }
        description = @common_helper.get_description(nexpose_identifier_id, row)
      elsif matching_fields.any? { |x| previous_row[x].nil? || previous_row[x] != row[x] }
        info = @common_helper.get_field_info(matching_fields, previous_row)
        @log.log_message("Generated ticket with #{info}")

        @ticket['fields']['description'] = @common_helper.print_description(description)
        tickets.push(@ticket.to_json)
        previous_row = nil
        description = nil
        redo
      else
        description = @common_helper.update_description(description, row)
      end
    end

    unless @ticket.nil? || @ticket.empty?
      @ticket['fields']['description'] = @common_helper.print_description(description)
      tickets.push(@ticket.to_json)
    end

    @log.log_message("Generated <#{tickets.count.to_s}> tickets.")
    tickets
  end

  # Sends ticket closure (in JSON format) to Jira individually (each ticket in the list
  # as a separate web service call).
  #
  # * *Args*    :
  #   - +tickets+ -  List of Jira ticket Keys to be closed.
  #
  def close_tickets(tickets)
    if tickets.nil? || tickets.empty?
      @log.log_message('No tickets to close.')
    else
      headers = { 'Content-Type' => 'application/json',
                  'Accept' => 'application/json' }

      tickets.each do |ticket|
        uri = URI.parse(("#{@jira_data[:jira_url]}#{ticket}/transitions"))
        req = Net::HTTP::Post.new(uri.to_s, headers)

        transition = get_jira_transition_details(ticket, @jira_data[:close_step_id])
        if transition.nil?
          #Valid transition could not be found. Ignore ticket since we do not know what to do with it.
          @log.log_message("No valid transition found for ticket <#{ticket}>. Skipping closure.")
          next
        end

        #We need to find any required fields to send with the transition request
        required_fields = []
        transition['fields'].each do |field|
          if field[1]['required'] == true
            # Currently only required fields with 'allowedValues' in the JSON response are supported.
            if not field[1].has_key? 'allowedValues'
              @log.log_message("Closing ticket <#{ticket}> requires a field I know nothing about! Transition details are <#{transition}>. Ignoring this field.")
              next
            else
              if field[1]['schema']['type'] == 'array'
                required_fields << "\"#{field[0]}\" : [{\"id\" : \"#{field[1]['allowedValues'][0]['id']}\"}]"
              else
                required_fields << "\"#{field[0]}\" : {\"id\" : \"#{field[1]['allowedValues'][0]['id']}\"}"
              end
            end
          end
        end

        req.body = "{\"transition\" : {\"id\" : #{transition['id']}}, \"fields\" : { #{required_fields.join(",")}}}"
        send_ticket(uri, req)
      end
    end
  end

  # Prepare ticket closures from the CSV of vulnerabilities exported from Nexpose.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of Jira ticket Keys to be closed.
  #
  def prepare_close_tickets(vulnerability_list, nexpose_identifier_id)
    @log.log_message('Preparing tickets to close.')
    @nxid = nil
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      @nxid = @common_helper.generate_nxid(nexpose_identifier_id, row)
      # Query Jira for the ticket by unique id (generated NXID)
      queried_key = get_jira_key("jql=project=#{@jira_data[:project]} AND description ~ \"NXID: #{@nxid}\" AND (status != #{@jira_data[:close_step_name]})&fields=key")
      if queried_key.nil? || queried_key.empty?
        @log.log_message("Error when closing tickets - query for NXID <#{@nxid}> should have returned a Jira key!!")
      else
        #Jira uses a post call to the ticket key path to close the ticket. The "prepared batch of tickets" in this case is just a collection Jira ticket keys to close.
        tickets.push(queried_key)
      end
    end
    tickets
  end

  # Sends ticket updates (in JSON format) to Jira individually (each ticket in the list as a
  # separate HTTP post).
  #
  # * *Args*    :
  #   - +tickets+ -  List of JSON-formatted ticket updates.
  #
  def update_tickets(tickets)
    if (tickets.nil? || tickets.empty?) then
      @log.log_message('No tickets to update.')
    else
      tickets.each do |ticket_details|
        headers = {'Content-Type' => 'application/json',
                   'Accept' => 'application/json'}

        (ticket_details.first.nil?) ? send_whole_ticket = true : send_whole_ticket = false

        url = "#{jira_data[:jira_url]}"
        url += "#{ticket_details.first}" unless send_whole_ticket
        uri = URI.parse(url)

        send_whole_ticket ? req = Net::HTTP::Post.new(uri.to_s, headers) : req = Net::HTTP::Put.new(uri.to_s, headers)

        send_whole_ticket ?
            req.body = ticket_details.last :
            req.body = {'update' => {'description' => [{'set' => "#{JSON.parse(ticket_details[1])['fields']['description']}"}]}}.to_json

        send_ticket(uri, req)
      end
    end
  end

  # Prepare ticket updates from the CSV of vulnerabilities exported from Nexpose.
  #
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #   - +nexpose_identifier_id+ -  Site/TAG ID the vulnerability list was generate from.
  #
  # * *Returns* :
  #   - List of JSON-formated tickets for updating within Jira.
  #
  def prepare_update_tickets(vulnerability_list, nexpose_identifier_id)
    fail 'Ticket updates are not supported in Default mode.' if @options[:ticket_mode] == 'D'
    @log.log_message('Preparing tickets to update.')
    #Jira uses the ticket key to push updates. Since new IPs won't have a Jira key, generate new tickets for all of the IPs found.
    updated_tickets = prepare_create_tickets(vulnerability_list, nexpose_identifier_id)

    tickets_to_send = []

    #Find the keys that exist (IPs that have tickets already)
    updated_tickets.each do |ticket|
      description = JSON.parse(ticket)['fields']['description']
      nxid_index = description.rindex("NXID")
      nxid = nxid_index.nil? ? nil : description[nxid_index..-1]

      if (nxid).nil?
        #Could not get NXID from the last line in the description. Do not push the invalid description.
        @log.log_message("Failed to parse the NXID from a generated ticket update! Ignoring ticket <#{nxid}>")
        next
      end
      queried_key = get_jira_key("jql=project=#{@jira_data[:project]} AND description ~ \"#{nxid.strip}\" AND (status != #{@jira_data[:close_step_name]})&fields=key")
      ticket_key_pair = []
      ticket_key_pair << queried_key
      ticket_key_pair << ticket
      tickets_to_send << ticket_key_pair
    end
    tickets_to_send
  end
end