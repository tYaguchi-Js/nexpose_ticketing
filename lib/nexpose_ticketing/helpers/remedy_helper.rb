require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'csv'
require 'savon'
require 'nexpose_ticketing/utilities/nx_logger'
require 'nexpose_ticketing/version'
require_relative './base_helper'

# Serves as the Remedy interface for creating/updating issues from 
# vulnelrabilities found in Nexpose.
class RemedyHelper < BaseHelper
  attr_accessor :log, :client
  def initialize(service_data, options, mode)
    super(service_data, options, mode)
  end

  # Generates a savon-based ticket object.
  #
  # * *Args*    :
  #   - +extra_fields+ -  List of mode-specific fields (hash) to be added to the ticket.
  #
  def generate_new_ticket(extra_fields=nil)
    base_ticket = {
      'First_Name' => "#{@service_data[:first_name]}",
        'Impact' => '1-Extensive/Widespread',
        'Last_Name' => "#{@service_data[:last_name]}",
        'Reported_Source' => 'Other',
        'Service_Type' => 'Infrastructure Event',
        'Status' => 'New',
        'Action' => 'CREATE',
        "Summary"=>"",
        "Notes"=>"",
        'Urgency' => '1-Critical',
    }
    extra_fields.each { |k, v| base_ticket[k.to_s] = v } if extra_fields
    base_ticket
  end

  # Sends a list of tickets (in SOAP format) to Remedy individually (each ticket in the list 
  # as a separate web service call).
  #
  # * *Args*    :
  #   - +wdsl+ -  XML file which describes the network service.
  #   - +endpoint+ -  Endpoint to which the data will be submitted.
  #
  def get_client(wdsl, endpoint)
    Savon.client(wsdl:  File.join(File.dirname(__FILE__), "../config/remedy_wsdl/#{wdsl}"),
                 adapter: :net_http,
                 ssl_verify_mode: :none,
                 open_timeout: @service_data[:open_timeout],
                 read_timeout: @service_data[:read_timeout],
                 endpoint: @service_data[endpoint.intern],
                 soap_header: { 'AuthenticationInfo' => 
                                  { 'userName' => "#{@service_data[:username]}",
                                    'password' => "#{@service_data[:password]}",
                                    'authentication' => "#{@service_data[:authentication]}"
                                   }
                              })
  end
  
  # Sends a list of tickets (in SOAP format) to Remedy individually (each ticket in the list 
  # as a separate web service call).
  #
  # * *Args*    :
  #   - +service+ -  The helpdesk service to which the tickets should be submitted.
  #   - +tickets+ -  List of savon-formatted (hash) ticket creates (new tickets).
  #
  def send_tickets(client, service, tickets)
    service_name = service.to_s.match(/desk_([a-z]*)_/)
    service_name = service_name.captures.first unless service_name.nil?
    tickets.each do |ticket|
      begin
        @log.log_message(ticket)
        response = client.call(service, message: ticket)
      rescue Savon::SOAPFault => e
        @log.log_message("SOAP exception in #{service_name} ticket: #{e.message}")
        raise
      rescue Savon::HTTPError => e
        @log.log_message("HTTP error in #{service_name} ticket: #{e.message}")
        raise
      end
    end
  end
    
  # Sends a list of tickets (in SOAP format) to Remedy individually (each ticket in the list 
  # as a separate web service call).
  #
  # * *Args*    :
  #   - +tickets+ -  List of savon-formatted (hash) ticket creates (new tickets).
  #
  def create_tickets(tickets)
    fail 'Ticket(s) cannot be empty' if tickets.nil? || tickets.empty?
    @metrics.created tickets.count
    client = get_client('HPD_IncidentInterface_Create_WS.xml', :create_soap_endpoint)
    send_tickets(client, :help_desk_submit_service, tickets)
  end

  # Sends ticket updates (in SOAP format) to Remedy individually (each ticket in the list 
  # as a separate web service call).
  #
  # * *Args*    :
  #   - +tickets+ -  List of savon-formatted (hash) ticket updates.
  #
  def update_tickets(tickets)
    if tickets.nil? || tickets.empty?
      @log.log_message("No tickets to update.")
      return
    end
    @metrics.updated tickets.count - @metrics.get_created
    client = get_client('HPD_IncidentInterface_WS.xml', :query_modify_soap_endpoint)
    send_tickets(client, :help_desk_modify_service, tickets)
  end
  
  # Sends ticket closure (in SOAP format) to Remedy individually (each ticket in the list 
  # as a separate web service call).
  #
  # * *Args*    :
  #   - +tickets+ -  List of savon-formatted (hash) ticket closures.
  #
  def close_tickets(tickets)
    if tickets.nil? || tickets.empty?
      @log.log_message("No tickets to close.")
      return
    end
    @metrics.closed tickets.count
    client = get_client('HPD_IncidentInterface_WS.xml', :query_modify_soap_endpoint)
    send_tickets(client, :help_desk_modify_service, tickets)
  end  
  
  # Sends a query (in SOAP format) to Remedy to return back a single ticket based on the criteria.
  #
  # * *Args*    :
  #   - +unique_id+ -  Unique identifier generated by the helper.
  #
  # * *Returns* :
  #   - Remedy incident information in hash format or nil if no results are found.
  #
  def query_for_ticket(unique_id)
    client = get_client('HPD_IncidentInterface_WS.xml', :query_modify_soap_endpoint)

    begin
      response = client.call(:help_desk_query_list_service, message: {'Qualification' => "'Status' < \"Closed\" AND 'Detailed Decription' LIKE \"%#{unique_id}%\""})
    rescue Savon::SOAPFault => e
      @log.log_message("SOAP exception in query ticket: #{e.message}")
      return if e.to_hash[:fault][:faultstring].index("ERROR (302)") == 0
      raise
    rescue Savon::HTTPError => e
      @log.log_message("HTTP error in query ticket: #{e.message}")
      raise
    end
    
    response.body[:help_desk_query_list_service_response][:get_list_values]
  end

  # Prepare tickets from the CSV of vulnerabilities exported from Nexpose. This method determines 
  # how to prepare the tickets (by default, by IP address or by vulnerability) based on config options.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for creating within Remedy.
  #
  def prepare_create_tickets(vulnerability_list, nexpose_identifier_id)
    @metrics.start
    @log.log_message('Preparing ticket requests...')
    prepare_tickets(vulnerability_list, nexpose_identifier_id)
  end

  # Prepare to update tickets from the CSV of vulnerabilities exported from Nexpose. This method determines
  # how to prepare the tickets for update (by IP address or by vulnerability) based on config options.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for creating within Remedy.
  #
  def prepare_update_tickets(vulnerability_list, nexpose_identifier_id)
    @metrics.start
    prepare_tickets(vulnerability_list, nexpose_identifier_id)
  end
  
  # Prepares a list of vulnerabilities into a list of savon-formatted tickets (incidents) for 
  # Remedy.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for creating within Remedy.
  #
  def prepare_tickets(vulnerability_list, nexpose_identifier_id)
    matching_fields = @mode_helper.get_matching_fields
    @ticket = Hash.new(-1)
    
    @log.log_message("Preparing tickets for #{@options[:ticket_mode]} mode.")
    tickets = []
    previous_row = nil
    description = nil
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      if previous_row.nil?
        previous_row = row.dup        
        description = @mode_helper.get_description(nexpose_identifier_id, row)
        @ticket = generate_new_ticket({'Summary' => "#{@mode_helper.get_title(row)}"[0...100],
                                        'Notes' => ""})
        #Skip querying for ticket if it's the initial scan
        next if row['comparison'].nil?
        
        # Query Remedy for the incident by unique id (generated NXID)
        queried_incident = query_for_ticket("NXID: #{@mode_helper.get_nxid(nexpose_identifier_id, row)}")
        if !queried_incident.nil? && queried_incident.first.is_a?(Hash)
          queried_incident.select! { |t| !['Closed', 'Resolved', 'Cancelled'].include?(t[:status]) }
        end

        if queried_incident.nil? || queried_incident.empty?
          @log.log_message("No incident found for NXID: #{@mode_helper.get_nxid(nexpose_identifier_id, row)}. Creating...")

          new_ticket_csv = vulnerability_list.split("\n").first
          new_ticket_csv += "\n#{row.to_s}"
          
          #delete the comparison row
          data = CSV::Table.new(CSV.parse(new_ticket_csv, headers: true))
          data.delete("comparison")

          new_ticket = prepare_create_tickets(data.to_s, nexpose_identifier_id)
          @log.log_message('Created ticket. Sending to Remedy...')
          create_tickets(new_ticket)
          @log.log_message('Ticket sent. Performing update for ticket...')
          #Now that there is a ticket for this NXID update it as if it existed this whole time...
          previous_row = nil
          redo
        else
          info = @mode_helper.get_field_info(matching_fields, previous_row)
          @log.log_message("Creating ticket update with #{info} for Nexpose Identifier with ID: #{nexpose_identifier_id}")
          @log.log_message("Ticket status #{row['comparison']}")
          # Remedy incident updates require populating all fields.
          @ticket = extract_queried_incident(queried_incident, "")
        end   
      elsif matching_fields.any? { |x| previous_row[x].nil? || previous_row[x] != row[x] }
        info = @mode_helper.get_field_info(matching_fields, previous_row)
        @log.log_message("Generated ticket with #{info}")

        @ticket['Notes'] = @mode_helper.print_description(description)
        tickets.push(@ticket)
        previous_row = nil
        description = nil
        redo
      else
        description = @mode_helper.update_description(description, row)        
      end
    end

    unless @ticket.nil? || @ticket.empty?
      info = @mode_helper.get_field_info(matching_fields, previous_row)
      @log.log_message("Creating ticket update with #{info} for Nexpose Identifier with ID: #{nexpose_identifier_id}")
      @ticket['Notes'] = @mode_helper.print_description(description)
      tickets.push(@ticket)
    end

    @log.log_message("Generated <#{tickets.count.to_s}> tickets.")
    tickets
  end

  # Creates a ticket with the extracted data from a queried Remedy incident.
  #
  #   - +queried_incident+ - The queried incident from Remedy
  #   - +notes_header+ - The texted to be placed at the top of the Remedy 'Notes' field.
  #   - +status+ - The status to which the ticket will be set.
  #
  # * *Returns* :
  #   - A single savon-formated (hash) ticket for updating within Remedy.
  #
  def ticket_from_queried_incident(queried_incident, notes_header, status)
    {
      'Categorization_Tier_1' => queried_incident[:categorization_tier_1],
      'Categorization_Tier_2' => queried_incident[:categorization_tier_2],
      'Categorization_Tier_3' => queried_incident[:categorization_tier_3],
      'Closure_Manufacturer' => queried_incident[:closure_manufacturer],
      'Closure_Product_Category_Tier1' => queried_incident[:closure_product_category_tier1],
      'Closure_Product_Category_Tier2' => queried_incident[:closure_product_category_tier2],
      'Closure_Product_Category_Tier3' => queried_incident[:closure_product_category_tier3],
      'Closure_Product_Model_Version' => queried_incident[:closure_product_model_version],
      'Closure_Product_Name' => queried_incident[:closure_product_name],
      'Company' => queried_incident[:company],
      'Summary' => queried_incident[:summary],
      'Notes' => notes_header || queried_incident[:notes],
      'Impact' => queried_incident[:impact],
      'Manufacturer' => queried_incident[:manufacturer],
      'Product_Categorization_Tier_1' => queried_incident[:product_categorization_tier_1],
      'Product_Categorization_Tier_2' => queried_incident[:product_categorization_tier_2],
      'Product_Categorization_Tier_3' => queried_incident[:product_categorization_tier_3],
      'Product_Model_Version' => queried_incident[:product_model_version],
      'Product_Name' => queried_incident[:product_name],
      'Reported_Source' => queried_incident[:reported_source],
      'Resolution' => queried_incident[:resolution],
      'Resolution_Category' => queried_incident[:resolution_category],
      'Resolution_Category_Tier_2' => queried_incident[:resolution_category_tier_2],
      'Resolution_Category_Tier_3' => queried_incident[:resolution_category_tier_3],
      'Resolution_Method' => queried_incident[:resolution_method],
      'Service_Type' => queried_incident[:service_type],
      'Status' => status || queried_incident[:status],
      'Urgency' => queried_incident[:urgency],
      'Action' => 'MODIFY',
      'Work_Info_Summary' => queried_incident[:work_info_summary],
      'Work_Info_Notes' => queried_incident[:work_info_notes],
      'Work_Info_Type' => queried_incident[:work_info_type],
      'Work_Info_Date' => queried_incident[:work_info_date],
      'Work_Info_Source' => queried_incident[:work_info_source],
      'Work_Info_Locked' => queried_incident[:work_info_locked],
      'Work_Info_View_Access' => queried_incident[:work_info_view_access],
      'Incident_Number' => queried_incident[:incident_number],
      'Status_Reason' => queried_incident[:status_reason],
      'ServiceCI' => queried_incident[:service_ci],
      'ServiceCI_ReconID' => queried_incident[:service_ci_recon_id],
      'HPD_CI' => queried_incident[:hpd_ci],
      'HPD_CI_ReconID' => queried_incident[:hpd_ci_recon_id],
      'HPD_CI_FormName' => queried_incident[:hpd_ci_form_name],
      'z1D_CI_FormName' => queried_incident[:z1d_ci_form_name]
    }
  end

  # Extracts from a queried Remedy incident the relevant data required for an update to be made to said incident.
  # Creates a ticket with the extracted data.
  #
  #   - +queried_incident+ - The queried incident from Remedy
  #   - +notes_header+ - The texted to be placed at the top of the Remedy 'Notes' field.
  #
  # * *Returns* :
  #   - A single savon-formated (hash) ticket for updating within Remedy.
  #
  def extract_queried_incident(queried_incident, notes_header)
    unless queried_incident.first.is_a?(Hash)
      return ticket_from_queried_incident(queried_incident, notes_header, nil) 
    end

    fail "Multiple tickets returned for same NXID" if queried_incident.count > 1 
    ticket_from_queried_incident(queried_incident.first, notes_header, nil)
  end

  # Prepare ticket closures from the CSV of vulnerabilities exported from Nexpose.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for closing within Remedy.
  #
  def prepare_close_tickets(vulnerability_list, nexpose_identifier_id)
    @log.log_message("Preparing ticket closures for mode #{@options[:ticket_mode]}.")
    @nxid = nil
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      @nxid = @mode_helper.get_nxid(nexpose_identifier_id, row)

      # Query Remedy for the incident by unique id (generated NXID)
      queried_incident = query_for_ticket("NXID: #{@nxid}")
      if queried_incident.nil? || queried_incident.empty?
        @log.log_message("No incident found for NXID: #{@nxid}")
      else
        # Remedy incident updates require populating all fields.
        ticket = ticket_from_queried_incident(queried_incident, nil, 'Closed')
        tickets.push(ticket)
      end
    end
    tickets
  end
end