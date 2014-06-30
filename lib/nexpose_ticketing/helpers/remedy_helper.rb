require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'csv'
require 'savon'
require 'nexpose_ticketing/nx_logger'

# Serves as the Remedy interface for creating/updating issues from 
# vulnelrabilities found in Nexpose.
class RemedyHelper
  attr_accessor :remedy_data, :options, :log, :client
  def initialize(remedy_data, options)
    @remedy_data = remedy_data
    @options = options
    @log = NexposeTicketing::NXLogger.new
  end
  
  # Sends a list of tickets (in SOAP format) to Remedy individually (each ticket in the list 
  # as a separate web service call).
  #
  # * *Args*    :
  #   - +tickets+ -  List of savon-formatted (hash) ticket creates (new tickets).
  #
  def create_tickets(tickets)
    fail 'Ticket(s) cannot be empty' if tickets.nil? || tickets.empty?
    client = Savon.client(wsdl:  File.join(File.dirname(__FILE__), '../config/remedy_wsdl/HPD_IncidentInterface_Create_WS.xml'),
                           ssl_verify_mode: :none,
                           open_timeout: @remedy_data[:open_timeout],
                           read_timeout: @remedy_data[:read_timeout],
                           endpoint: @remedy_data[:create_soap_endpoint],
                           soap_header: { 'AuthenticationInfo' => 
                                          { 'userName' => "#{@remedy_data[:username]}",
                                            'password' => "#{@remedy_data[:password]}",
                                            'authentication' => "#{@remedy_data[:authentication]}"
                                          }
                                        })
    tickets.each do |ticket|
      begin
        @log.log_message(ticket)
        response = client.call(:help_desk_submit_service, message: ticket)
      rescue Savon::SOAPFault => e
        @log.log_message("SOAP exception in create ticket: #{e.message}")
        raise
      rescue Savon::HTTPError => e
        @log.log_message("HTTP error in create ticket: #{e.message}")
        raise
      end
    end
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
    else
      client = Savon.client(wsdl:  File.join(File.dirname(__FILE__), '../config/remedy_wsdl/HPD_IncidentInterface_WS.xml'),
                             ssl_verify_mode: :none,
                             open_timeout: @remedy_data[:open_timeout],
                             read_timeout: @remedy_data[:read_timeout],
                             endpoint: @remedy_data[:query_modify_soap_endpoint],
                             soap_header: { 'AuthenticationInfo' => 
                                            { 'userName' => "#{@remedy_data[:username]}",
                                              'password' => "#{@remedy_data[:password]}",
                                              'authentication' => "#{@remedy_data[:authentication]}"
                                            }
                                          })
      tickets.each do |ticket|
        begin
          response = client.call(:help_desk_modify_service, message: ticket)
        rescue Savon::SOAPFault => e
          @log.log_message("SOAP exception in create ticket: #{e.message}")
          raise
        rescue Savon::HTTPError => e
          @log.log_message("HTTP error in create ticket: #{e.message}")
          raise
        end
      end
    end
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
    else
      client = Savon.client(wsdl:  File.join(File.dirname(__FILE__), '../config/remedy_wsdl/HPD_IncidentInterface_WS.xml'),
                             ssl_verify_mode: :none,
                             open_timeout: @remedy_data[:open_timeout],
                             read_timeout: @remedy_data[:read_timeout],
                             endpoint: @remedy_data[:query_modify_soap_endpoint],
                             soap_header: { 'AuthenticationInfo' => 
                                            { 'userName' => "#{@remedy_data[:username]}",
                                              'password' => "#{@remedy_data[:password]}",
                                              'authentication' => "#{@remedy_data[:authentication]}"
                                            }
                                          })
      tickets.each do |ticket|
        begin
          response = client.call(:help_desk_modify_service, message: ticket)
        rescue Savon::SOAPFault => e
          @log.log_message("SOAP exception in create ticket: #{e.message}")
          raise
        rescue Savon::HTTPError => e
          @log.log_message("HTTP error in create ticket: #{e.message}")
          raise
        end
      end
    end
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
    client = Savon.client(wsdl: File.join(File.dirname(__FILE__), '../config/remedy_wsdl/HPD_IncidentInterface_WS.xml'),
                               ssl_verify_mode: :none,
                               open_timeout: @remedy_data[:open_timeout],
                               read_timeout: @remedy_data[:read_timeout],
                               endpoint: @remedy_data[:query_modify_soap_endpoint],
                               soap_header: { 'AuthenticationInfo' => 
                                              { 'userName' => "#{@remedy_data[:username]}",
                                                'password' => "#{@remedy_data[:password]}",
                                                'authentication' => "#{@remedy_data[:authentication]}"
                                              }
                                            })
    begin
      response = client.call(:help_desk_query_list_service, message: {'Qualification' => "'Detailed Decription' LIKE \"%#{unique_id}%\""})
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
  # how to prepare the tickets (either by default or by IP address) based on config options.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for creating within Remedy.
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
  
  # Prepares a list of vulnerabilities into a list of savon-formatted tickets (incidents) for 
  # Remedy. The preparation by default means that each vulnerability within Nexpose is a 
  # separate incident within Remedy.  This makes for smaller, more actionalble incidents but 
  # could lead to a very large total number of incidents.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for creating within Remedy.
  #
  def prepare_create_tickets_default(vulnerability_list)
    @log.log_message("Preparing tickets by default method.")
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      # NXID in the notes is a unique identifier used to query incidents to update/resolve 
      # incidents as they are resolved in Nexpose.
      ticket = {
        'First_Name' => "#{@remedy_data[:first_name]}",
        'Impact' => '1-Extensive/Widespread',
        'Last_Name' => "#{@remedy_data[:last_name]}",
        'Reported_Source' => 'Other',
        'Service_Type' => 'Infrastructure Event',
        'Status' => 'New',
        'Action' => 'CREATE',
        'Summary' => "#{row['ip_address']} => #{row['summary']}",
        'Notes' => "Summary: #{row['summary']} \n\nFix: #{row['fix']} \n\nURL: #{row['url']}
                    \n\nNXID: #{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}",                              
        'Urgency' => '1-Critical'
      }
      tickets.push(ticket)
    end
    tickets
  end
  
  # Prepares a list of vulnerabilities into a list of savon-formatted tickets (incidents) for 
  # Remedy. The preparation by IP means that all vulnerabilities within Nexpose for one IP 
  # address are consolidated into a single Remedy incident. This reduces the number of incidents
  # within ServiceNow but greatly increases the size of the work notes.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for creating within Remedy.
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
          'First_Name' => "#{@remedy_data[:first_name]}",
          'Impact' => '1-Extensive/Widespread',
          'Last_Name' => "#{@remedy_data[:last_name]}",
          'Reported_Source' => 'Other',
          'Service_Type' => 'Infrastructure Event',
          'Status' => 'New',
          'Action' => 'CREATE',
          'Summary' => "#{row['ip_address']} => Vulnerabilities",
          'Notes' => "++ New Vulnerabilities +++++++++++++++++++++++++++++++++++++\n",
          'Urgency' => '1-Critical'
        }
      end
      if current_ip == row['ip_address']
        @ticket['Notes'] += 
          "\n\n========================================== \nSummary: #{row['summary']} \nFix: #{row['fix']}"
        unless row['url'].nil?
          @ticket['Notes'] += 
            "\nURL: #{row['url']}"
        end
      end
      unless current_ip == row['ip_address']
        # NXID in the work_notes is the unique identifier used to query incidents to update them.
        @ticket['Notes'] += "\n\nNXID: #{current_ip}"
        tickets.push(@ticket)
        current_ip = -1
        redo
      end
    end
    # NXID in the work_notes is the unique identifier used to query incidents to update them.
    @ticket['Notes'] += "\n\nNXID: #{current_ip}"
    tickets.push(@ticket) unless @ticket.nil?
    tickets
  end
  
  # Prepare ticket updates from the CSV of vulnerabilities exported from Nexpose. This method 
  # currently only supports updating IP-address mode tickets in Remedy. The list of vulnerabilities 
  # are ordered by IP address and then by ticket_status, allowing the method to loop through and  
  # display new, old, and same vulnerabilities in that order.
  #
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for updating within Remedy.
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
        
        # Query Remedy for the incident by unique id (generated NXID)
        queried_incident = query_for_ticket("NXID: #{row['ip_address']}")
        if queried_incident.nil? || queried_incident.empty?
          @log.log_message("No incident found for NXID: #{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}") 
        else
          @log.log_message("Creating ticket update with IP address: #{row['ip_address']}")
          @log.log_message("Ticket status #{ticket_status}")
          # Remedy incident updates require populating all fields.
          @ticket = {
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
            'Notes' => "++ #{row['comparison']} Vulnerabilities +++++++++++++++++++++++++++++++++++++\n",
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
            'Status' => queried_incident[:status],
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
      end
      if current_ip == row['ip_address']
        # If the ticket_status is different, add a a new 'header' to signify a new block of tickets.
        unless ticket_status == row['comparison']
          @ticket['Notes'] += 
            "\n\n\n++ #{row['comparison']} Vulnerabilities +++++++++++++++++++++++++++++++++++++\n"
          ticket_status = row['comparison']
        end
        
        @ticket['Notes'] += 
          "\n\n========================================== \nSummary: #{row['summary']} \nFix: #{row['fix']}"
        # Only add the URL block if data exists in the row.
        unless row['url'].nil?
          @ticket['Notes'] += 
            "\nURL: #{row['url']}"
        end
      end
      unless current_ip == row['ip_address']
        # NXID in the work_notes is the unique identifier used to query incidents to update them.
        @ticket['Notes'] += "\n\nNXID: #{current_ip}"
        tickets.push(@ticket)
        current_ip = -1
        redo
      end
    end
    # NXID in the work_notes is the unique identifier used to query incidents to update them.
    @ticket['Notes'] += "\n\nNXID: #{current_ip}"
    tickets.push(@ticket) unless @ticket.nil?
    tickets
  end
  
  # Prepare ticket closures from the CSV of vulnerabilities exported from Nexpose. This method 
  # currently only supports updating default mode tickets in ServiceNow.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for closing within Remedy.
  #
  def prepare_close_tickets(vulnerability_list)
    fail 'Ticket closures are only supported in default mode.' if @options[:ticket_mode] == 'I'
    @log.log_message("Preparing ticket closures by default method.")
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      # Query Remedy for the incident by unique id (generated NXID)
      queried_incident = query_for_ticket("NXID: #{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}")
      if queried_incident.nil? || queried_incident.empty?
        @log.log_message("No incident found for NXID: #{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}") 
      else
        # Remedy incident updates require populating all fields.
        ticket = {
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
          'Notes' => queried_incident[:notes],
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
          'Status' => 'Closed',
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
        tickets.push(ticket)
      end
    end
    tickets
  end
end
