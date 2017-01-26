require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'csv'
require 'nexpose_ticketing/nx_logger'
require 'nexpose_ticketing/version'
require_relative './base_helper'

# This class serves as the JIRA interface
# that creates issues within JIRA from vulnerabilities
# found in Nexpose.
# Copyright:: Copyright (c) 2014 Rapid7, LLC.
class JiraHelper < BaseHelper
  def initialize(service_data, options, mode)
    super(service_data, options, mode)
  end

  # Fetches the Jira ticket key e.g INT-1. This is required to post updates to the Jira.
  #
  # * *Args*    :
  #   - +JQL query string+ -  Jira's Query Language string used to search for a ticket key.
  #
  # * *Returns* :
  #   - Jira ticket key if found, nil otherwise.
  #
  def get_jira_key(jql_query, nxid = nil)
    fail 'JQL query string cannot be empty.' if jql_query.empty?
    headers = { 'Content-Type' => 'application/json',
                'Accept' => 'application/json' }

    uri = URI.parse(("#{@service_data[:jira_url]}".split("/")[0..-2].join('/') + '/search'))
    uri.query = [uri.query, URI.escape(jql_query)].compact.join('&')
    req = Net::HTTP::Get.new(uri.to_s, headers)
    response = send_jira_request(uri, req)

    issues = JSON.parse(response.body)['issues']

    if issues.nil? || !issues.any?
      @log.log_message "JIRA did not return any keys for query containing NXID #{nxid}"
      return nil
    end

    if issues.size > 1
      # If Jira returns more than one key for a "unique" NXID query result then something has gone wrong...
      # Safest response is to return no key and let logic elsewhere dictate the action to take.
      error = "Jira returned multiple keys for query containing NXID #{nxid}."
      error += " Please check project within JIRA."
      error += " Response was <#{issues}>"
      @log.log_error_message(error)
      return nil
    end

   issues[0]['key']
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
    request.basic_auth @service_data[:username], @service_data[:password]
    resp = Net::HTTP.new(uri.host, uri.port)

    # Enable this line for debugging the https call.
    # resp.set_debug_output(@log)

    resp.use_ssl = uri.scheme == 'https'
    resp.verify_mode = OpenSSL::SSL::VERIFY_NONE

    return resp.request(request) unless ticket

    resp.start do |http|
      res = http.request(request)
      code = res.code.to_i

      next if code.between?(200,299)

      unless code.between?(400, 499)
        @log.log_error_message("Error submitting ticket data: #{res.message}, #{res.body}")
        return res
      end

      @log.log_error_message("Unable to access JIRA.")
      @log.log_error_message "Error code: #{code}"

      #Bad project etc
      case code
      when 400
        errors = res.body.scan(/errors":{(.+)}}/).first.first
        errors = errors.gsub('"', '').gsub(':', ': ').gsub(',', "\n")
        @log.log_error_message "Error messages:\n#{errors}"
      #Log in failed
      when 401
        @log.log_error_message "Message: #{res.message.strip}"
        @log.log_error_message "Reason: #{res['x-seraph-loginreason']}"
      #Locked out
      when 403
        @log.log_error_message "Message: #{res.message.strip}"
        @log.log_error_message "Reason: #{res['x-seraph-loginreason']}"
        @log.log_error_message "#{res['x-authentication-denied-reason']}"
      else
        #e.g. 404 - bad URL
        @log.log_error_message "Message: #{res.message.strip}"
      end

      return res
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

    uri = URI.parse(("#{@service_data[:jira_url]}#{jira_key}/transitions?expand=transitions.fields."))
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
    error = "Response was <#{transitions}> and desired close Step ID was <#{@service_data[:close_step_id]}>. Jira returned no valid transition to close the ticket!"
    @log.log_message(error)
    return nil
  end

  def create_tickets(tickets)
    fail 'Ticket(s) cannot be empty.' if tickets.nil? || tickets.empty?
    created_tickets = 0

    tickets.each do |ticket|
      headers = { 'Content-Type' => 'application/json',
                  'Accept' => 'application/json' }

      uri = URI.parse("#{@service_data[:jira_url]}")

      req = Net::HTTP::Post.new(uri, headers)
      req.body = ticket
      
      response = send_ticket(uri, req)
      code = response.nil? ? 1 : response.code.to_i
      break if code.between?(400, 499)

      created_tickets += 1
    end

    @metrics.created created_tickets
  end

  # Prepares tickets from the CSV.
  def prepare_create_tickets(vulnerability_list, nexpose_identifier_id)
    @metrics.start
    @log.log_message('Preparing ticket requests...')
    matching_fields = @mode_helper.get_matching_fields
    
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
                    'key' => "#{@service_data[:project]}" },
                'summary' => @mode_helper.get_title(row),
                'description' => '',
                'issuetype' => {
                    'name' => 'Task' }
            }
        }
        description = @mode_helper.get_description(nexpose_identifier_id, row)
      elsif matching_fields.any? { |x| previous_row[x].nil? || previous_row[x] != row[x] }
        info = @mode_helper.get_field_info(matching_fields, previous_row)
        @log.log_message("Generated ticket with #{info}")

        @ticket['fields']['description'] = @mode_helper.print_description(description)
        tickets.push(@ticket.to_json)
        previous_row = nil
        description = nil
        redo
      else
        description = @mode_helper.update_description(description, row)
      end
    end

    unless @ticket.nil? || @ticket.empty?
      info = @mode_helper.get_field_info(matching_fields, previous_row)
      @log.log_message("Generated ticket with #{info}")
      @ticket['fields']['description'] = @mode_helper.print_description(description)
      tickets.push(@ticket.to_json)
    end

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
      return
    end
    closed_count = 0

    headers = { 'Content-Type' => 'application/json',
                'Accept' => 'application/json' }

    tickets.each do |ticket|
      uri = URI.parse(("#{@service_data[:jira_url]}#{ticket}/transitions"))
      req = Net::HTTP::Post.new(uri.to_s, headers)

      transition = get_jira_transition_details(ticket, @service_data[:close_step_id])
      if transition.nil?
        #Valid transition could not be found. Ignore ticket since we do not know what to do with it.
        @log.log_message("No valid transition found for ticket <#{ticket}>. Skipping closure.")
        next
      end

      #We need to find any required fields to send with the transition request
      required_fields = []
      transition['fields'].each do |field|
        next unless field[1]['required'] == true
          
        # Currently only required fields with 'allowedValues' in the JSON response are supported.
        if not field[1].has_key? 'allowedValues'
          @log.log_message("Closing ticket <#{ticket}> requires a field I know nothing about! Transition details are <#{transition}>. Ignoring this field.")
            next
        end
        val = "{\"id\" : \"#{field[1]['allowedValues'][0]['id']}\"}"
        val = "[#{field}]" if field[1]['schema']['type'] == 'array'
        required_fields <<  "\"#{field[0]}\" : #{val}"
      end

      req.body = "{\"transition\" : {\"id\" : #{transition['id']}}, \"fields\" : { #{required_fields.join(",")}}}"
      response = send_ticket(uri, req)
      code = response.nil? ? 1 : response.code.to_i
      break if code.between?(400, 499)

      closed_count += 1
    end

    @metrics.closed closed_count
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
      @nxid = @mode_helper.get_nxid(nexpose_identifier_id, row)
      # Query Jira for the ticket by unique id (generated NXID)
      query_string = "jql=project=#{@service_data[:project]} AND description ~ \"NXID: #{@nxid}\" AND (status != #{@service_data[:close_step_name]})&fields=key"
      queried_key = get_jira_key(query_string, @nxid)
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
      
        create_new_ticket = ticket_details.first.nil?

        url = "#{service_data[:jira_url]}"

        if create_new_ticket
          req = Net::HTTP::Post.new(url, headers)
          req.body = ticket_details.last
        else
          url += "#{ticket_details[0]}"
          req = Net::HTTP::Put.new(url, headers)
          req.body = {'update' => {'description' => [{'set' => "#{JSON.parse(ticket_details[1])['fields']['description']}"}]}}.to_json
        end

        response = send_ticket(URI.parse(url), req)
        code = response.nil? ? 1 : response.code.to_i
        break if code.between?(400, 499)
         
        if create_new_ticket
          @metrics.created
        else
          @metrics.updated
        end
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
    @metrics.start
    return unless @mode_helper.updates_supported?
    
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

      query_string = "jql=project=#{@service_data[:project]} AND description ~ \"#{nxid.strip}\" AND (status != #{@service_data[:close_step_name]})&fields=key"
      queried_key = get_jira_key(query_string, nxid)
      ticket_key_pair = []
      ticket_key_pair << queried_key
      ticket_key_pair << ticket
      tickets_to_send << ticket_key_pair
    end
    tickets_to_send
  end
end