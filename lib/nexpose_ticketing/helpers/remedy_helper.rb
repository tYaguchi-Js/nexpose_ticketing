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
  # how to prepare the tickets (by default, by IP address or by vulnerability) based on config options.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for creating within Remedy.
  #
  def prepare_create_tickets(vulnerability_list, site_id)
    @ticket = Hash.new(-1)
    case @options[:ticket_mode]
    # 'D' Default mode: IP *-* Vulnerability
    when 'D'
      prepare_create_tickets_default(vulnerability_list, site_id)
    # 'I' IP address mode: IP address -* Vulnerability
    when 'I'
      prepare_create_tickets_by_ip(vulnerability_list, site_id)
    # 'V' Vulnerability mode: Vulnerability -* IP address
    when 'V'
      prepare_create_tickets_by_vulnerability(vulnerability_list, site_id)
    else
      fail 'No ticketing mode selected.'
    end
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
  def prepare_update_tickets(vulnerability_list, site_id)
    @ticket = Hash.new(-1)
    case @options[:ticket_mode]
      # 'I' IP address mode: IP address -* Vulnerability
      when 'I'
        prepare_update_tickets_by_ip(vulnerability_list, site_id)
      # 'V' Vulnerability mode: Vulnerability -* IP address
      when 'V'
        prepare_update_tickets_by_vulnerability(vulnerability_list, site_id)
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
  def prepare_create_tickets_default(vulnerability_list, site_id)
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
                    \n\nNXID: #{site_id}#{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}",
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
  def prepare_create_tickets_by_ip(vulnerability_list, site_id)
    @log.log_message('Preparing tickets by IP address.')
    tickets = []
    current_ip = -1
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      if current_ip == -1 
        current_ip = row['ip_address']
        @log.log_message("Creating ticket with IP address: #{row['ip_address']}, Asset ID:  #{row['asset_id']} and Site ID: #{site_id}")
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
        @ticket['Notes'] += "\n\nNXID: #{site_id}#{current_ip}"
        tickets.push(@ticket)
        current_ip = -1
        redo
      end
    end
    # NXID in the work_notes is the unique identifier used to query incidents to update them.
    @ticket['Notes'] += "\n\nNXID: #{site_id}#{current_ip}"
    tickets.push(@ticket) unless @ticket.nil?
    tickets
  end


  # Prepares a list of vulnerabilities into a list of savon-formatted tickets (incidents) for
  # Remedy. The preparation by vulnerability means that all IP addresses within Nexpose for one vulnerability
  # are consolidated into a single Remedy incident. This reduces the number of incidents
  # within ServiceNow but greatly increases the size of the work notes.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for creating within Remedy.
  #
  def prepare_create_tickets_by_vulnerability(vulnerability_list, site_id)
    @log.log_message("Preparing tickets by vulnerability.")
    tickets = []
    current_vuln_id = -1
    current_solution_id = -1
    current_asset_id = -1
    full_summary = nil
    vulnerability_list_header = vulnerability_list[0]
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
    #New vulnerability ID (the query sorting criteria).
    if current_vuln_id == -1
      current_vuln_id = row['vulnerability_id']
      current_solution_id = row['solution_id']
      current_asset_id =  row['asset_id']
      @log.log_message("Creating ticket with vulnerability id: #{row['vulnerability_id']}, Asset ID:  #{row['asset_id']} and Site ID: #{site_id}")
      summary = "Vulnerability: #{row['title']}"

      #Remedy has a summary field max size of 100 so truncate any summaries that are larger than that and place the full summary in the notes.
      if summary.length > 100
        full_summary = summary += "\n\n\n"
        summary = summary[0..96]
        summary += '...'
      else
        full_summary = nil
      end

      @ticket = {
          'First_Name' => "#{@remedy_data[:first_name]}",
          'Impact' => '1-Extensive/Widespread',
          'Last_Name' => "#{@remedy_data[:last_name]}",
          'Reported_Source' => 'Other',
          'Service_Type' => 'Infrastructure Event',
          'Status' => 'New',
          'Action' => 'CREATE',
          'Summary' => summary,
          'Full_Summary' => summary,
          'Assets' => "++ Assets affected +++++++++++++++++++++++\n",
          'Solutions' =>  "++ Details ++++++++++++++++++++++++++\n",
          'Notes' => "++ Additional information ++++++++++++++++\n",
          'Urgency' => '1-Critical'
      }
      @ticket['Solutions'] +=
          "\n\n========================================== \nSummary: #{row['summary']} \nFix: #{row['fix']}"
      @ticket['Assets'] +=
          "#{row['ip_address']}"
    end
    if current_vuln_id == row['vulnerability_id']
      #Add solutions for the now affected assets.
      if current_solution_id != row['solution_id']
        new_solution_text =  "\n========================================== \nSummary: #{row['summary']} \nFix: #{row['fix']}\n"
        if  @ticket['Solutions'].include? new_solution_text
          @log.log_message('Ignoring duplicate solution in ticket creation.')
        else
          @ticket['Solutions'] += new_solution_text
          #Add any references.
          unless row['url'].nil?
            @ticket['Solutions'] += "\nURL: #{row['url']}"
          end
        end
        current_solution_id = row['solution_id']
      end

      #Added the new asset to the list of affected systems if it is different (could have been the same asset with a different solution ID).
      if current_asset_id != row['asset_id']
        @ticket['Assets'] += ", #{row['ip_address']}"
        current_asset_id = row['asset_id']
      end
    end
    unless current_vuln_id == row['vulnerability_id']
      # NXID in the work_notes is the unique identifier used to query incidents to update them.
      @ticket['Notes'] += "\n\nNXID: #{site_id}#{current_asset_id}#{current_vuln_id}"
      current_vuln_id = -1
      current_solution_id = -1
      current_asset_id = -1
      @ticket = format_notes_by_vulnerability(@ticket, full_summary)
      tickets.push(@ticket)
      redo
    end
  end
  # NXID in the work_notes is the unique identifier used to query incidents to update them.
  @ticket['Notes'] += "\n\nNXID: #{site_id}#{current_asset_id}#{current_vuln_id}"
  @ticket = format_notes_by_vulnerability(@ticket, full_summary)
  tickets.push(@ticket) unless @ticket.nil?
  tickets
  end

  def format_notes_by_vulnerability(ticket, prepend)
    nxid_holder = ticket['Notes']
    ticket['Notes'] = ''
    ticket['Notes'] += prepend unless prepend.nil?
    ticket['Notes'] += ticket['Assets'] += "\n\n"
    ticket['Notes'] += ticket['Solutions'] += "\n\n"
    ticket['Notes'] += nxid_holder
    ticket.delete("Assets")
    ticket.delete("Solutions")
    ticket.delete("Full_Summary")
    ticket
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
  def prepare_update_tickets_by_ip(vulnerability_list, site_id)
    fail 'Ticket updates are only supported in IP-address mode.' if @options[:ticket_mode] != 'I'
    @ticket = Hash.new(-1)
    
    @log.log_message('Preparing ticket updates by IP address.')
    tickets = []
    current_ip = -1
    ticket_status = 'New'
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      if current_ip == -1 
        current_ip = row['ip_address']
        ticket_status = row['comparison']
        
        # Query Remedy for the incident by unique id (generated NXID)
        queried_incident = query_for_ticket("NXID: #{site_id}#{row['ip_address']}")
        if queried_incident.nil? || queried_incident.empty?
          @log.log_message("No incident found for NXID: #{site_id}#{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}")
        else
          @log.log_message("Creating ticket update with IP address: #{row['ip_address']} for site with ID: #{site_id}")
          @log.log_message("Ticket status #{ticket_status}")
          # Remedy incident updates require populating all fields.
          @ticket = extract_queried_incident(queried_incident, "++ #{row['comparison']} Vulnerabilities ++++++++++++++++++++++++++\n")
          end
      end
      if current_ip == row['ip_address']
        # If the ticket_status is different, add a a new 'header' to signify a new block of tickets.
        unless ticket_status == row['comparison']
          @ticket['Notes'] += 
            "\n\n\n++ #{row['comparison']} Vulnerabilities ++++++++++++++++++++++++++\n"
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
        @ticket['Notes'] += "\n\nNXID: #{site_id}#{current_ip}"
        tickets.push(@ticket)
        current_ip = -1
        redo
      end
    end
    # NXID in the work_notes is the unique identifier used to query incidents to update them.
    @ticket['Notes'] += "\n\nNXID: #{site_id}#{current_ip}" unless @ticket.empty?
    tickets.push(@ticket) unless @ticket.nil? || @ticket.empty?
    tickets
  end

  # Prepare ticket updates from the CSV of vulnerabilities exported from Nexpose. This method
  # currently only supports updating vulnerability mode tickets in Remedy. The list of vulnerabilities
  # are ordered by vulnerability ID and then by ticket_status, allowing the method to loop through and
  # display new, old, and same vulnerabilities in that order.
  #
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for updating within Remedy.
  #
  def prepare_update_tickets_by_vulnerability(vulnerability_list, site_id)
    fail 'Ticket updates are only supported in IP-address mode.' if @options[:ticket_mode] != 'V'
    @ticket = Hash.new(-1)

    @log.log_message('Preparing ticket updates by IP address.')
    tickets = []
    current_vuln_id = -1
    current_solution_id = -1
    current_asset_id = -1
    current_solutions_text = "\n++ Details ++++++++++++++\n"
    ticket_status = 'New'
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      if current_vuln_id == -1
        current_solutions_text = "\n++ Details +++++++++++++++\n"
        current_vuln_id = row['vulnerability_id']
        ticket_status = row['comparison']
        current_asset_id = -1
        current_solution_id = -1

        # Query Remedy for the incident by unique id (generated NXID)
        queried_incident = query_for_ticket("NXID: #{site_id}#{row['asset_id']}#{row['vulnerability_id']}")
        if queried_incident.nil? || queried_incident.empty?
          @log.log_message("No incident found for NXID: #{site_id}#{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}. Creating...")
          new_ticket_csv = vulnerability_list.split("\n").first
          new_ticket_csv += "\n#{row.to_s}"
          new_ticket = prepare_create_tickets_by_vulnerability(new_ticket_csv, site_id)
          @log.log_message('Created ticket. Sending to Remedy...')
          create_tickets(new_ticket)
          @log.log_message('Ticket sent. Performing update for ticket...')
          #Now that there is a ticket for this NXID update it as if it existed this whole time...
          current_vuln_id = -1
          redo
        else
          @log.log_message("Creating ticket update for vulnerability with ID: #{row['vulnerability_id']}, Asset ID:  #{row['asset_id']} and Site ID: #{site_id}. Ticket status #{ticket_status}.")
          # Remedy incident updates require populating all fields.
          @ticket = extract_queried_incident(queried_incident, "++ #{row['comparison']} Assets ++++++++++++++++++++++\n")
        end
      end
      if current_vuln_id == row['vulnerability_id']
        # If the ticket_status is different, add a a new 'header' to signify a new block of tickets.
        unless ticket_status == row['comparison']
          @ticket['Notes'] +=
              "\n\n\n++ #{row['comparison']} Assets +++++++++++++++++++++++\n"
          ticket_status = row['comparison']
        end

        #Added the new asset to the list of affected systems if it is different (could have been the same asset with a different solution ID).
        if current_asset_id != row['asset_id']
          @ticket['Notes'] += "#{row['ip_address']}, "
          current_asset_id = row['asset_id']
        end

        #Add solutions for the now affected assets.
        if current_solution_id != row['solution_id']
          new_solution_text =  "\n========================================== \nSummary: #{row['summary']} \nFix: #{row['fix']}\n"
          if current_solutions_text.include? new_solution_text
            @log.log_message('Ignoring duplicate solution for ticket update.')
          else
          current_solutions_text += new_solution_text
            #Add any references.
            unless row['url'].nil?
              current_solutions_text +=
                  "\nURL: #{row['url']}"
            end
          end
          current_solution_id = row['solution_id']
        end
      end
      unless current_vuln_id == row['vulnerability_id']
        # NXID in the work_notes is the unique identifier used to query incidents to update them.
        @ticket['Notes'] += "\n\n" + current_solutions_text
        @ticket['Notes'] += "\n\nNXID: #{site_id}#{current_asset_id}#{current_vuln_id}"
        tickets.push(@ticket)
        current_vuln_id = -1
        current_solution_id = -1
        current_asset_id = -1
        redo
      end
    end
    # NXID in the work_notes is the unique identifier used to query incidents to update them.
    @ticket['Notes'] += current_solutions_text
    @ticket['Notes'] += "\n\nNXID: #{site_id}#{current_asset_id}#{current_vuln_id}" unless @ticket.empty?
    tickets.push(@ticket) unless @ticket.nil? || @ticket.empty?
    tickets
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

    if queried_incident[0].is_a?(Hash)
      #Hash of hashes
      @log.log_message("More than one ticket returned from Remedy. Number of tickets returned: #{queried_incident.count}. Parsing return to check returned ticket status...")
      @ticket = nil
      queried_incident.count.times do |x|
        #TODO: This should be moved to the config for the Remedy helper.
        if ['Closed', 'Resolved', 'Cancelled'].include? queried_incident[x][:status]
          @log.log_message("Returned ticket number <#{x}> of <#{(queried_incident.count - 1)}> is of status <#{queried_incident[x][:status]}>. Ignoring.")
        else
          fail 'When trying to update tickets Remedy returned multiple tickets with the same NXID and in progress status!' unless @ticket.nil?
          @ticket = {
              'Categorization_Tier_1' => queried_incident[x][:categorization_tier_1],
              'Categorization_Tier_2' => queried_incident[x][:categorization_tier_2],
              'Categorization_Tier_3' => queried_incident[x][:categorization_tier_3],
              'Closure_Manufacturer' => queried_incident[x][:closure_manufacturer],
              'Closure_Product_Category_Tier1' => queried_incident[x][:closure_product_category_tier1],
              'Closure_Product_Category_Tier2' => queried_incident[x][:closure_product_category_tier2],
              'Closure_Product_Category_Tier3' => queried_incident[x][:closure_product_category_tier3],
              'Closure_Product_Model_Version' => queried_incident[x][:closure_product_model_version],
              'Closure_Product_Name' => queried_incident[x][:closure_product_name],
              'Company' => queried_incident[x][:company],
              'Summary' => queried_incident[x][:summary],
              'Notes' => notes_header,
              'Impact' => queried_incident[x][:impact],
              'Manufacturer' => queried_incident[x][:manufacturer],
              'Product_Categorization_Tier_1' => queried_incident[x][:product_categorization_tier_1],
              'Product_Categorization_Tier_2' => queried_incident[x][:product_categorization_tier_2],
              'Product_Categorization_Tier_3' => queried_incident[x][:product_categorization_tier_3],
              'Product_Model_Version' => queried_incident[x][:product_model_version],
              'Product_Name' => queried_incident[x][:product_name],
              'Reported_Source' => queried_incident[x][:reported_source],
              'Resolution' => queried_incident[x][:resolution],
              'Resolution_Category' => queried_incident[x][:resolution_category],
              'Resolution_Category_Tier_2' => queried_incident[x][:resolution_category_tier_2],
              'Resolution_Category_Tier_3' => queried_incident[x][:resolution_category_tier_3],
              'Resolution_Method' => queried_incident[x][:resolution_method],
              'Service_Type' => queried_incident[x][:service_type],
              'Status' => queried_incident[x][:status],
              'Urgency' => queried_incident[x][:urgency],
              'Action' => 'MODIFY',
              'Work_Info_Summary' => queried_incident[x][:work_info_summary],
              'Work_Info_Notes' => queried_incident[x][:work_info_notes],
              'Work_Info_Type' => queried_incident[x][:work_info_type],
              'Work_Info_Date' => queried_incident[x][:work_info_date],
              'Work_Info_Source' => queried_incident[x][:work_info_source],
              'Work_Info_Locked' => queried_incident[x][:work_info_locked],
              'Work_Info_View_Access' => queried_incident[x][:work_info_view_access],
              'Incident_Number' => queried_incident[x][:incident_number],
              'Status_Reason' => queried_incident[x][:status_reason],
              'ServiceCI' => queried_incident[x][:service_ci],
              'ServiceCI_ReconID' => queried_incident[x][:service_ci_recon_id],
              'HPD_CI' => queried_incident[x][:hpd_ci],
              'HPD_CI_ReconID' => queried_incident[x][:hpd_ci_recon_id],
              'HPD_CI_FormName' => queried_incident[x][:hpd_ci_form_name],
              'z1D_CI_FormName' => queried_incident[x][:z1d_ci_form_name]
          }
        end
      end
    else
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
          'Notes' => notes_header,
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
    @ticket
  end


  # Prepare ticket closures from the CSV of vulnerabilities exported from Nexpose.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for closing within Remedy.
  #
  def prepare_close_tickets(vulnerability_list, site_id)
    fail 'Ticket closures are only supported in default mode.' if @options[:ticket_mode] == 'I'
    @log.log_message('Preparing ticket closures by default method.')
    @nxid = nil
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      case @options[:ticket_mode]
        # 'D' Default mode: IP *-* Vulnerability
        when 'D'
          @nxid = "#{site_id}#{row['asset_id']}#{row['vulnerability_id']}#{row['solution_id']}"
        # 'I' IP address mode: IP address -* Vulnerability
        when 'I'
          @nxid = "#{site_id}#{row['current_ip']}"
        # 'V' Vulnerability mode: Vulnerability -* IP address
        when 'V'
          @nxid = "#{site_id}#{row['current_asset_id']}#{row['current_vuln_id']}"
        else
          fail 'Could not close tickets - do not understand the ticketing mode!'
      end
      # Query Remedy for the incident by unique id (generated NXID)
      queried_incident = query_for_ticket("NXID: #{@nxid}")
      if queried_incident.nil? || queried_incident.empty?
        @log.log_message("No incident found for NXID: #{@nxid}")
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
