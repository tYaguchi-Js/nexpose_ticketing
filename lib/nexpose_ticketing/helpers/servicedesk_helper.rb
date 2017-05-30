require 'net/http'
require 'nokogiri'
require 'dbm'
require_relative './base_helper'
require 'nexpose_ticketing/utilities/nx_logger'
require 'nexpose_ticketing/version'

class ServiceDeskHelper < BaseHelper
  attr_accessor :log

  def initialize(service_data, options, mode)
    super(service_data, options, mode)

    @rest_uri = service_data[:rest_uri]
    @api_key = service_data[:api_key]
    @ticket_db_path = service_data[:ticket_db_path]
  end


  def open_database()
    DBM.open(@ticket_db_path, 0600, DBM::WRCREAT)
  end


  def add_ticket_to_database(workorderid, nxid)
    @log.log_message("Adding ticket <#{workorderid}> for NXID <#{nxid}> to local db.")
    db = open_database()
    db[nxid] = workorderid
    db.close()
  end


  def find_ticket_in_database(nxid) 
    @log.log_message("Finding workorder id for NXID <#{nxid}> from local db.")
    db = open_database()
    begin
      workorderid = db[nxid]
      @log.log_message("Lookup found incident <#{workorderid}> in the db.")
    rescue Exception => e
      @log.log_message("Threw an exception accessing the dbm <#{e.class} #{e} #{e.message}>.")
      raise e
    end
    db.close()

    workorderid
  end


  def remove_tickets_from_database(tickets)
    db = open_database()
    tickets.each do |t|
      nxid = t[:nxid]
      @log.log_message("Removing workorder id from database for NXID <#{nxid}>")
      db.delete(nxid) unless db[nxid].nil?
    end
    db.close()
  end


  def prepare_create_tickets(vulnerability_list, nexpose_identifier_id)
    @log.log_message('Preparing ticket creation...')
    tickets = prepare_tickets(vulnerability_list, nexpose_identifier_id)

    tickets.each { |ticket| @log.log_message("Prepared ticket: #{ticket}")}
    tickets
  end


  def prepare_tickets(vulnerability_list, nexpose_identifier_id)
    @metrics.start
    @log.log_message("Preparing ticket for #{@options[:ticket_mode]} mode.")
    matching_fields = @mode_helper.get_matching_fields
    tickets = []
    host_vulns={}
    previous_row = nil
    description = nil
    nxid = nil

    initial_scan = false

    CSV.parse( vulnerability_list.chomp, headers: :first_row )  do |row|
      initial_scan = initial_scan || row['comparison'].nil?
        
      if previous_row.nil?
        nxid = @mode_helper.get_nxid(nexpose_identifier_id, row)
        previous_row = row.dup
        description = @mode_helper.get_description(nexpose_identifier_id, row)  

        host_vulns[nxid] = { :ip => row['ip_address'], 
                             :description => "",
                             :title => @mode_helper.get_title(row) } 
      elsif matching_fields.any? {  |x| previous_row[x].nil? || previous_row[x] != row[x] }
        info = @mode_helper.get_field_info(matching_fields, previous_row)
        @log.log_message("Generated ticket with #{info}")

        host_vulns[nxid][:description] = @mode_helper.print_description(description)
        previous_row = nil
        description = nil
        redo
      else
        description = @mode_helper.update_description(description, row)
      end
    end

    unless host_vulns[nxid].nil? || host_vulns[nxid].empty?
      host_vulns[nxid][:description] = @mode_helper.print_description(description)
    end

    host_vulns.each do |nxid, vuln_info|
      workorderid = initial_scan ? nil : find_ticket_in_database(nxid)
      if workorderid.nil? || workorderid.empty?
        @log.log_message("Creating new incident for assetid #{nxid}")
        @metrics.created
        tickets << { :action => :create, :nxid => nxid,
                     :description => create_ticket_request(vuln_info[:title], vuln_info[:description]) }
      else
        @log.log_message("Updating incident for assetid #{nxid}")
        @metrics.updated
        tickets << { :action => :modify, :nxid => nxid, 
                     :workorderid => workorderid,
                     :description => modify_ticket_request(vuln_info[:description]) }
      end
    end
    tickets
  end

  ## Uses the configured or default options to set up a ticket creation request
  def create_ticket_request(subject, description)
    request = Nokogiri::XML::Builder.new do |xml|
      xml.Operation {
        xml.Details {
          xml.parameter {
            xml.name {
                xml.text 'requester'
            }
            xml.value {
              xml.text @service_data[:requester]
            }
          }
          xml.parameter {
            xml.name {
              xml.text 'Group'
            }
            xml.value {
              xml.text @service_data[:group]
            }
          }
          xml.parameter {
            xml.name {
              xml.text 'subject'
            }
            xml.value {
              xml.text subject
            }
          }
          xml.parameter {
            xml.name {
              xml.text 'description'
            }
            xml.value {
              xml.cdata description
            }
          }
        }
      }
    end
    request.to_xml
  end

  def modify_ticket_request(description)
#         modifyRequest = """
# <Operation>
#     <Details>
#         <parameter>
#             <name>description</name>
#             <value>#{description}</value>
#         </parameter>
#     </Details>
# </Operation>
# """
    doc = Nokogiri::XML::Builder.new() do |xml|
      xml.Operation {
        xml.Details {
          xml.parameter {
            xml.name {
                xml.text 'requester'
            }
            xml.value {
              xml.text @service_data[:requester]
            }
          }
          xml.parameter {
            xml.name {
              xml.text 'description'
            }
            xml.value {
              xml.cdata description
            }
          }
        }
      }
    end
    doc.to_xml
  end

  def submit_ticket(ticket)
    @log.log_message("Connecting to #{@rest_uri}.")
    uri = URI( @rest_uri )
    res = Net::HTTP::post_form(uri,
                               'OPERATION_NAME' => 'ADD_REQUEST',
                               'TECHNICIAN_KEY' => @api_key,
                               'INPUT_DATA' => ticket[:description])

    response = Nokogiri::XML.parse(res.read_body)
    begin
      status = response.xpath('//statuscode').text
      status_code = status.empty? ? -1 : Integer(status)
    
      if status_code != 200
        @log.log_message("Unable to create ticket #{ticket}, got response #{response.to_xml}")
        return
      end

      workorderid = Integer(response.xpath('//workorderid').text)
    rescue ArgumentError => ae
      @log.log_message("Failed to parse response from servicedesk #{response}")
      raise ae
    end

    @log.log_message( "created ticket #{workorderid}")
    add_ticket_to_database( workorderid, ticket[:nxid] )
  end


  def modify_ticket(ticket)
    @log.log_message("Connecting to #{@rest_uri}/#{ticket[:workorderid]}")
    uri = URI( "#{@rest_uri}/#{ticket[:workorderid]}")
    res = Net::HTTP::post_form(uri,
                               'OPERATION_NAME' => 'EDIT_REQUEST',
                               'TECHNICIAN_KEY' => @api_key,
                               'INPUT_DATA' => ticket[:description])

    response = Nokogiri::XML.parse(res.read_body)
    begin
      status = Integer(response.xpath('//statuscode').text)
    rescue Exception => e
      @log.log_message("XML request was #{ticket[:description]} response is #{response.to_xml}")
      raise e
    end
    
    unless status == 200
      @log.log_message("Unable to modify ticket #{ticket}, got response #{response.to_xml}")
    end
  end


  def close_ticket(ticket)
    @log.log_message("Connecting to #{@rest_uri}/#{ticket[:workorderid]}")
    uri = URI( "#{@rest_uri}/#{ticket[:workorderid]}" )
    res = Net::HTTP::post_form(uri,
                               'OPERATION_NAME' => 'CLOSE_REQUEST',
                               'TECHNICIAN_KEY' => @api_key)

    response = Nokogiri::XML.parse(res.read_body)
    begin
      status = Integer(response.xpath('//statuscode').text)
    rescue Exception => e
      @log.log_message("XML request was #{ticket[:description]} response is #{response.to_xml}")
      raise e
    end

    unless status == 200
      @log.log_message("Unable to close ticket #{ticket}, got response #{response.to_xml}")
    end
  end


  def create_tickets(tickets)
    @log.log_message("Creating tickets on server at #{@rest_uri}")

    tickets.each { |ticket| submit_ticket(ticket) }
  end


  def prepare_update_tickets(vulnerability_list, nexpose_identifier_id)
    @log.log_message('Preparing ticket updates...')
    prepare_tickets(vulnerability_list, nexpose_identifier_id)
  end


  def update_tickets(tickets)
    @log.log_message('Updating tickets')
    tickets.each do |ticket|
      if ticket[:action] == :create
        @log.log_message('Creating ticket')
        submit_ticket(ticket)
      else
        @log.log_message("Updating ticket #{ticket[:workorderid]}")
        modify_ticket(ticket)
      end
    end
  end

  # Prepare ticket closures from the CSV of vulnerabilities exported from Nexpose.
  #
  # * *Args*    :
  #   - +vulnerability_list+ -  CSV of vulnerabilities within Nexpose.
  #
  # * *Returns* :
  #   - List of savon-formated (hash) tickets for closing within ServiceDesk.
  #
  def prepare_close_tickets(vulnerability_list, nexpose_identifier_id)
    @log.log_message("Preparing ticket closures for mode #{@options[:ticket_mode]}.")
    @nxid = nil
    tickets = []
    CSV.parse(vulnerability_list.chomp, headers: :first_row)  do |row|
      @nxid = @mode_helper.get_nxid(nexpose_identifier_id, row)

      workorderid = find_ticket_in_database(@nxid)
      # Query ServiceDesk for the incident by unique id (generated NXID)
      if workorderid.nil? || workorderid.empty?
        @log.log_message("No workorderid found for NXID #{@nxid}")
      else
        tickets << { :action => :close, :nxid => @nxid, 
                     :workorderid => workorderid,
                     :description => 'Automatically closing ticket.' }
      end
    end
    tickets
  end



  def close_tickets( tickets )
    to_close = tickets.select { |t| t[:action] == :close && !t[:workorderid].nil? }
    @metrics.closed to_close.count
    to_close.each { |ticket| close_ticket(ticket) }
    remove_tickets_from_database(tickets)
  end
end