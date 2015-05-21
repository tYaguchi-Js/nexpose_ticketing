require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'csv'
require 'nexpose_ticketing/nx_logger'

# This class serves as the JIRA interface
# that creates issues within JIRA from vulnerabilities
# found in Nexpose.
# Copyright:: Copyright (c) 2014 Rapid7, LLC.
class JiraHelper
  # TODO: Add V Mode.
  # TODO: Allow updates/closed loop.
  attr_accessor :jira_data, :options
  def initialize(jira_data, options)
    @jira_data = jira_data
    @options = options
    @log = NexposeTicketing::NXLogger.new
  end

  # Generates the NXID. The NXID is a unique identifier used to find and update and/or close tickets.
  #
  # * *Args*    :
  #   - +site_id+ -  Site ID the tickets are being generated for. Required for all ticketing modes
  #   - +row+ -  Row from the generated Nexpose CSV report. Required for default ('D') mode.
  #   - +current_ip+ -  The IP address of that this ticket is for. Required for IP mode ('I') mode.
  #
  # * *Returns* :
  #   - NXID string.
  #
  def generate_nxid(site_id, row=nil, current_ip=nil)
    fail 'Site ID is required to generate the NXID.' if site_id.empty?
    case @options[:ticket_mode]
      # 'D' Default mode: IP *-* Vulnerability
      when 'D'
        fail 'Row is required to generate the NXID in \'D\' mode.' if row.nil? || row.empty?
        @nxid = "#{site_id}#{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}"
      # 'I' IP address mode: IP address -* Vulnerability
      when 'I'
        fail 'Current IP is required to generate the NXID in \'I\' mode.' if current_ip.nil? || current_ip.empty?
        @nxid = "#{site_id}#{current_ip.tr('.','')}"
      # 'V' mode net yet implemented.
      # 'V' Vulnerability mode: Vulnerability -* IP address
      #          when 'V'
      #            @NXID = "#{site_id}#{row['current_asset_id']}#{row['current_vuln_id']}"
      else
        fail 'Could not close tickets - do not understand the ticketing mode!'
    end
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
    req.basic_auth @jira_data[:username], @jira_data[:password]
    resp = Net::HTTP.new(uri.host, uri.port)

    # Enable this line for debugging the https call.
    # resp.set_debug_output(@log)

    resp.use_ssl = true if uri.scheme == 'https'
    resp.verify_mode = OpenSSL::SSL::VERIFY_NONE
    response = resp.request(req)

    issues = JSON.parse(response.body)['issues']
   if issues.nil? || !issues.any? || issues.size > 1
     # If Jira returns more than one key for a "unique" NXID query result then something has gone wrong...
     # Safest response is to return no key and let logic elsewhere dictate the action to take.
     @log.log_message("Jira returned no key or too many keys for query result! Response was <#{issues}>")
     return nil
   end
    return issues[0]['key']
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
    req.basic_auth @jira_data[:username], @jira_data[:password]
    resp = Net::HTTP.new(uri.host, uri.port)

    # Enable this line for debugging the https call.
    # resp.set_debug_output(@log)

    resp.use_ssl = true if uri.scheme == 'https'
    resp.verify_mode = OpenSSL::SSL::VERIFY_NONE

    response = resp.request(req)

    transitions = JSON.parse(response.body)

    if transitions.has_key? 'transitions'
      transitions['transitions'].each do |transition|
        if transition['to']['id'] == step_id.to_s
          return transition
        end
      end
    end
    @log.log_message("Jira returned no valid transition to close the ticket! Response was <#{transitions}> and desired close Step ID was <#{@jira_data[:close_step_id]}>.")
    return nil
  end

  def create_tickets(tickets)
    fail 'Ticket(s) cannot be empty.' if tickets.empty? || tickets.nil?
    tickets.each do |ticket|
      headers = { 'Content-Type' => 'application/json',
                  'Accept' => 'application/json' }

      uri = URI.parse("#{@jira_data[:jira_url]}")
      req = Net::HTTP::Post.new(@jira_data[:jira_url], headers)
      req.basic_auth @jira_data[:username], @jira_data[:password]
      req.body = ticket
      resp = Net::HTTP.new(uri.host, uri.port)

      # Enable this line for debugging the https call.
      #resp.set_debug_output(@log)

      resp.use_ssl = true if uri.scheme == 'https'
      resp.verify_mode = OpenSSL::SSL::VERIFY_NONE
      resp.start { |http| http.request(req) }
    end
  end

  # Prepares tickets from the CSV.
  # TODO Implement V Version.
  def prepare_create_tickets(vulnerability_list, site_id)
    @ticket = Hash.new(-1)
    case @options[:ticket_mode]
    # 'D' Default IP *-* Vulnerability
    when 'D'
      prepare_tickets_default(vulnerability_list, site_id)
    # 'I' IP address -* Vulnerability
    when 'I'
      prepare_tickets_by_ip(vulnerability_list, site_id)
    else
        fail 'Unsupported ticketing mode selected.'
    end
  end

  # Prepares and creates tickets in default mode.
  def prepare_tickets_default(vulnerability_list, site_id)
    @log.log_message('Preparing tickets for default mode.')
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row) do |row|
      # JiraHelper doesn't like new line characters in their summaries.
      summary = row['summary'].gsub(/\n/, ' ')
      ticket = {
          'fields' => {
              'project' => {
                  'key' => "#{@jira_data[:project]}" },
              'summary' => "#{row['ip_address']} => #{summary}",
              'description' => "CVSS Score: #{row['cvss_score']} \n\n #{row['fix']} \n\n #{row['url']} \n\n\n NXID: #{generate_nxid(site_id, row)}",
              'issuetype' => {
                  'name' => 'Task' }
          }
      }.to_json
      tickets.push(ticket)
    end
    tickets
  end

  # Prepare tickets from the CSV of vulnerabilities exported from Nexpose. This method batches tickets 
  # per IP i.e. any vulnerabilities for a single IP in one ticket
  #
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #   - +site_id+ -  Site ID the vulnerability list was generate from.
  #
  # * *Returns* :
  #   - List of JSON-formatted tickets for updating within Jira.
  #
  def prepare_tickets_by_ip(vulnerability_list, site_id)
    @log.log_message('Preparing tickets for IP mode.')
    tickets = []
    current_ip = -1
    CSV.parse(vulnerability_list.chomp, headers: :first_row) do |row|
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
      # TODO: Better formatting this.
      if current_ip == row['ip_address']
        @ticket['fields']['description'] +=
        "\n ==============================\n\n
        #{row['summary']} \n CVSS Score: #{row['cvss_score']}
        \n\n ==============================\n
        \n Source: #{row['source']}, Reference: #{row['reference']}
        \n
        \n First seen: #{row['first_discovered']}
        \n Last seen: #{row['most_recently_discovered']}
        \n Fix:
        \n #{row['fix']}\n\n #{row['url']}
        \n
        \n\n"
      end
      unless current_ip == row['ip_address']
        @ticket['fields']['description'] += "\n\n\n NXID: #{generate_nxid(site_id, row, current_ip)}"
        tickets.push(@ticket.to_json)
        current_ip = -1
        redo
      end
    end
    @ticket['fields']['description'] += "\n\n\n NXID: #{generate_nxid(site_id, nil, current_ip)}"
    tickets.push(@ticket.to_json) unless @ticket.nil?
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

      tickets.each { |ticket|
        uri = URI.parse(("#{@jira_data[:jira_url]}#{ticket}/transitions"))
        req = Net::HTTP::Post.new(uri.to_s, headers)
        req.basic_auth @jira_data[:username], @jira_data[:password]

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
        resp = Net::HTTP.new(uri.host, uri.port)

        # Enable this line for debugging the https call.
        #resp.set_debug_output(@log)

        resp.use_ssl = true if uri.scheme == 'https'
        resp.verify_mode = OpenSSL::SSL::VERIFY_NONE
        resp.start { |http| http.request(req) }
      }
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
  def prepare_close_tickets(vulnerability_list, site_id)
    @log.log_message('Preparing tickets to close.')
    @nxid = nil
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      @nxid = generate_nxid(site_id, nil, row['ip_address'])
      # Query Jira for the ticket by unique id (generated NXID)
      queried_key = get_jira_key("jql=project=#{@jira_data[:project]} AND description ~ \"NXID: #{@nxid}\" AND (status != #{@jira_data[:close_step_name]})&fields=key")
      if queried_key.nil? || queried_key.empty?
        @log.log_message("Error when closing tickets - query for NXID <#{@nxid}> should have returned a Jira key!!")
      else
        #Jira uses a post call to the ticket key path to close the ticket. The "prepared batch of tickets" in this case is just a collection Jira ticket key's to close.
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

        req.basic_auth @jira_data[:username], @jira_data[:password]
        send_whole_ticket ?
            req.body = ticket_details.last :
            req.body = {'update' => {'description' => [{'set' => "#{JSON.parse(ticket_details[1])['fields']['description']}"}]}}.to_json

        resp = Net::HTTP.new(uri.host, uri.port)

        # Enable this line for debugging the https call.
        #resp.set_debug_output(@log)

        resp.use_ssl = true if uri.scheme == 'https'
        resp.verify_mode = OpenSSL::SSL::VERIFY_NONE
        resp.start { |http| http.request(req) }
      end
    end
  end

  # Prepare ticket updates from the CSV of vulnerabilities exported from Nexpose. This method batches tickets 
  # per IP i.e. any vulnerabilities for a single IP in one ticket
  #
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #   - +site_id+ -  Site ID the vulnerability list was generate from.
  #
  # * *Returns* :
  #   - List of JSON-formated tickets for updating within Jira.
  #
  def prepare_update_tickets(vulnerability_list, site_id)
    fail 'Ticket updates are only supported in IP-address mode.' if @options[:ticket_mode] != 'I'
    @log.log_message('Preparing tickets to update.')
    #Jira uses the ticket key to push updates. Since new IPs won't have a Jira key, generate new tickets for all of the IPs found.
    updated_tickets = prepare_tickets_by_ip(vulnerability_list, site_id)
    tickets_to_send = []

    #Find the keys that exist (IPs that have tickets already)
    updated_tickets.each do |ticket|
      nxid = JSON.parse(ticket)['fields']['description'].squeeze("\n").lines.to_a.last
      if (nxid.slice! "NXID:").nil?
        #Could not get NXID from the last line in the description. Do not push the invalid description.
        @log.log_message("Failed to parse the NXID from a generated ticket update! Ignoring ticket <#{nxid}>")
        next
      end
      queried_key = get_jira_key("jql=project=#{@jira_data[:project]} AND description ~ \"NXID: #{nxid.strip}\" AND (status != #{@jira_data[:close_step_name]})&fields=key")
      ticket_key_pair = []
      ticket_key_pair << queried_key
      ticket_key_pair << ticket
      tickets_to_send << ticket_key_pair
    end
    tickets_to_send
  end
end
