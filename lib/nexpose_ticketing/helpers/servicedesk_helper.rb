require 'net/http'
require 'nokogiri'
require 'dbm'

class ServiceDeskHelper
    attr_accessor :servicedesk_data, :options, :log

    def initialize(servicedesk_data, options)
        @servicedesk_data = servicedesk_data
        @options = options
        @log = NexposeTicketing::NXLogger.new

        @rest_uri = servicedesk_data[:rest_uri]
        @api_key = servicedesk_data[:api_key]
        @ticket_db_path = servicedesk_data[:ticket_db_path]
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

        return workorderid
    end


    def remove_ticket_from_database(nxid)
        @log.log_message("Removing workorder id from database for NXID <#{nxid}>")
        db = open_database()
        db.delete(nxid)
        db.close()
    end

    def prepare_create_tickets(vulnerability_list, site_id)
        @log.log_message('Preparing ticket requests...')
        case @options[:ticket_mode]
            # 'D' Default mode: IP *-* Vulnerability
            when 'D'
                tickets = create_tickets_by_default(vulnerability_list, site_id)
            # 'I' IP address mode: IP address -* Vulnerability
            when 'I'
                tickets = create_tickets_by_ip(vulnerability_list, site_id)
            else
                fail 'No ticketing mode selected.'
        end

        tickets.each { |ticket| @log.log_message("Prepared ticket: #{ticket}")}
        return tickets
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
                            xml.text @servicedesk_data[:requestor]
                        }
                    }
                    xml.parameter {
                        xml.name {
                            xml.text 'Group'
                        }
                        xml.value {
                            xml.text @servicedesk_data[:group]
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
        return request.to_xml
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
                        xml.text 'Description'
                    }
                    xml.value {
                        xml.cdata description
                    }
                }
            }

        }
        end

        return doc.to_xml
    end

    ## Given a bunch of vulnerabilities that passed the filters, make tickets for each one
    def create_tickets_by_default(vulnerability_list, site_id)
        @log.log_message('Preparing tickets by vulnerability...')
        tickets = []
        CSV.parse( vulnerability_list.chomp, headers: :first_row )  do |vuln|
            subject = "#{vuln['ip_address']}: #{vuln['summary']}"
            description = "Host: #{ip_address}\nSummary: #{vuln['summary']}\nFix: #{vuln['fix']}\nURL: #{vuln['url']}"

            tickets << { :action => :create, :nxid => "#{site_id}#{vuln['asset_id']}#{vuln['vulnerability_id']}#{vuln['solution_id']}",
                         :description => create_ticket_request( subject, description ) }
        end
        return tickets
    end


    def create_tickets_by_ip(vulnerability_list, site_id)
        @log.log_message('Preparing tickets by ip')
        tickets = []
        hostVulns = {}
        CSV.parse( vulnerability_list.chomp, headers: :first_row )  do |vuln|
            hostVulns["#{site_id}#{vuln['ip_address']}"] = { :ip => vuln['ip_address'], :description => "" } if not hostVulns.has_key?(vuln['asset_id'])
            hostVulns["#{site_id}#{vuln['ip_address']}"][:description] += "Summary: #{vuln['summary']}\nFix: #{vuln['fix']}\nURL: #{vuln['url']}\n\n"
        end

        hostVulns.each do |nxid, vulnInfo|
            tickets << { :action => :create, :nxid => nxid,
                         :description => create_ticket_request( "Vulnerabilities on #{vulnInfo[:ip]}", vulnInfo[:description] ) }
        end
        return tickets
    end


    def submit_ticket(ticket)
        @log.log_message("Connecting to #{@rest_uri}.")
        uri = URI( @rest_uri )
        res = Net::HTTP::post_form( uri,
                            'OPERATION_NAME' => 'ADD_REQUEST',
                            'TECHNICIAN_KEY' => @api_key,
                            'INPUT_DATA' => ticket[:description] )

        response = Nokogiri::XML.parse( res.read_body )
        status = Integer(response.xpath('//statuscode').text)
        
        if status != 200
            @log.log_message("Unable to create ticket #{ticket}, got response #{response.to_xml}")
            return
        end

        workorderid = Integer(response.xpath('//workorderid').text)

        @log.log_message( "created ticket #{workorderid}")
        add_ticket_to_database( workorderid, ticket[:nxid] )
    end


    def modify_ticket(ticket)
        @log.log_message("Connecting to #{@rest_uri}/#{ticket[:workorderid]}")
        uri = URI( "#{@rest_uri}/#{ticket[:workorderid]}" )
        res = Net::HTTP::post_form( uri,
                            'OPERATION_NAME' => 'EDIT_REQUEST',
                            'TECHNICIAN_KEY' => @api_key,
                            'INPUT_DATA' => ticket[:description] )

        response = Nokogiri::XML.parse( res.read_body )
        begin
            status = Integer(response.xpath('//statuscode').text)
        rescue Exception => e
            @log.log_message("XML request was #{ticket[:description]} response is #{response.to_xml}")
            raise e
        end
        
        if status != 200
            @log.log_message("Unable to modify ticket #{ticket}, got response #{response.to_xml}")
            return
        end
    end


    def close_ticket(ticket)
        @log.log_message("Connecting to #{@rest_uri}/#{ticket[:workorderid]}")
        uri = URI( "#{@rest_uri}/#{ticket[:workorderid]}" )
        res = Net::HTTP::post_form( uri,
                            'OPERATION_NAME' => 'CLOSE_REQUEST',
                            'TECHNICIAN_KEY' => @api_key )

        response = Nokogiri::XML.parse( res.read_body )
        begin
            status = Integer(response.xpath('//statuscode').text)
        rescue Exception => e
            @log.log_message("XML request was #{ticket[:description]} response is #{response.to_xml}")
            raise e
        end

        if status != 200
            @log.log_message("Unable to close ticket #{ticket}, got response #{response.to_xml}")
            return
        end

    end


    def create_tickets(tickets)
        @log.log_message("Creating tickets on server at #{@rest_uri}")

        tickets.each { |ticket| submit_ticket(ticket) }
    end

    
    def prepare_update_tickets(vulnerability_list, site_id)
        fail 'Ticket updates are only supported in IP-address mode.' if @options[:ticket_mode] != 'I'

        @log.log_message('Preparing ticket updates by IP address.')
        tickets = []
        hostVulns={}
        CSV.parse( vulnerability_list.chomp, headers: :first_row )  do |vuln|
            hostVulns["#{site_id}#{vuln['ip_address']}"] = { :ip => vuln['ip_address'], :description => "" } if not hostVulns.has_key?(vuln['asset_id'])
            hostVulns["#{site_id}#{vuln['ip_address']}"][:description] += "Summary: #{vuln['summary']}\nFix: #{vuln['fix']}\nURL: #{vuln['url']}\n\n"
        end

        hostVulns.each do |nxid, vulnInfo|
            workorderid = find_ticket_in_database(nxid)
            if workorderid.nil? || workorderid.empty?
                @log.log_message("No incident found for assetid #{nxid}, using defaults")
                tickets << { :action => :create, :nxid => nxid,
                             :description => create_ticket_request("Vulnerabilities on #{vulnInfo[:ip]}", vulnInfo[:description]) }
            else
                tickets << { :action => :modifty, :nxid => nxid, :workorderid => workorderid,
                             :description => modify_ticket_request( vulnInfo[:description] ) }
            end
        end
        return tickets
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
#          when 'V'
#            @NXID = "#{site_id}#{row['current_asset_id']}#{row['current_vuln_id']}"
          else
            fail 'Could not close tickets - do not understand the ticketing mode!'
        end
        workorderid = find_ticket_in_database(@nxid)
        # Query ServiceDesk for the incident by unique id (generated NXID)
        if workorderid.nil? || workorderid.empty?
          @log.log_message("No workorderid found for NXID #{@nxid}")
        else
            tickets << { :action => :close, :nxid => @nxid, :workorderid => workorderid,
                         :description => closeTicketRequest() }
        end
      end
      return tickets
    end


    def close_tickets( tickets )
        tickets.each { |ticket| close_ticket(ticket) if ticket[:action] == close && !ticket[:workorderid].nil?}
    end
end