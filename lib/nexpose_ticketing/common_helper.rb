module NexposeTicketing
  class CommonHelper
    MAX_NUM_REFS = 3
    
    def initialize(options)
      @ticketing_mode = options[:ticket_mode]
    end

    # Gets the base description hash from the relevant mode-specific method
    # which can converted into a finished description.
    #
    #   - +nexpose_id+ - The site or tag indentifier.
    #   - +options+ -  The options read from the ticket config file.
    #
    # * *Returns* :
    #   - Hash containing ticket description information.
    #
    def get_description(nexpose_id, row)
      description = { nxid: "NXID: #{generate_nxid(nexpose_id, row)}" }
      case @ticketing_mode
      when 'D' then get_default_ticket_description(description, row)
      when 'I' then get_ip_ticket_description(description, row)
      when 'V' then get_vuln_ticket_description(description, row)
      else fail "Ticketing mode #{@ticketing_mode} not recognised."
      end
    end

    # Updates an existing description hash containing information
    # necessary to generate a ticket description.
    # Note that Default mode tickets may not be updated.
    #
    #   - +description+ - The existing ticket hash to be updated.
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - Hash containing ticket description information.
    #
    def update_description(description, row)
      case @ticketing_mode
      when 'I' then return update_ip_ticket_description(description, row)
      when 'V' then return update_vuln_ticket_description(description, row)
      else description
      end
    end

    # Generates a final description string based on a description hash.
    #
    #   - +description+ - The finished ticket hash to be converted.
    #
    # * *Returns* :
    #   - String containing ticket description text.
    #
    def print_description(description)
      ticket = case @ticketing_mode
               when 'D' then print_default_ticket_description(description)
               when 'I' then print_ip_ticket_description(description)
               when 'V' then print_vuln_ticket_description(description)
               else fail "Ticketing mode #{@ticketing_mode} not recognised."
               end
      ticket << "\n\n\n#{description[:nxid]}"
      ticket
    end

    # Generates a hash containing the information necessary
    # to generate a Default-mode ticket description.
    #
    #   - +description+ - Base ticket hash with NXID.
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - Hash containing ticket description information.
    #
    def get_default_ticket_description(description, row)
      description[:header] = get_vuln_header(row)
      description[:header] << get_discovery_info(row)
      description[:references] = get_references(row)
      description[:solutions] = get_solutions(row)
      description
    end

    # Generates a hash containing the information necessary
    # to generate an IP-mode ticket description.
    #
    #   - +description+ - Base ticket hash with NXID.
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - Hash containing ticket description information.
    #
    def get_ip_ticket_description(description, row)
      description[:vulnerabilities] = []

      status = row['comparison']
      vuln_info = "++ #{status} Vulnerabilities ++\n" if !status.nil?
      description[:ticket_status] = status

      vuln_info = vuln_info.to_s + get_vuln_info(row)
      description[:vulnerabilities] << vuln_info
      description
    end

    # Generates a hash containing the information necessary
    # to generate a Vulnerability-mode ticket description.
    #
    #   - +description+ - Base ticket hash with NXID.
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - Hash containing ticket description information.
    #
    def get_vuln_ticket_description(description, row)
      description[:header] = get_vuln_header(row)
      description[:references] = get_references(row)
      description[:solutions] = get_solutions(row)
      description[:assets] = get_assets(row)
      description
    end
    
    # Updates an existing IP-mode description hash containing information
    # necessary to generate a ticket description.
    #
    #   - +description+ - The existing ticket hash to be updated.
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - Hash containing updated ticket description information.
    #
    def update_ip_ticket_description(description, row)
      status = row['comparison']
      header = "++ #{status} Vulnerabilities ++\n"
      header = "" unless description[:ticket_status] != status
  
      description[:vulnerabilities] << "#{header}#{get_vuln_info(row)}"
      description
    end

    # Updates an existing Vulnerability-mode description hash containing 
    # information necessary to generate a ticket description.
    #
    #   - +description+ - The existing ticket hash to be updated.
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - Hash containing updated ticket description information.
    #
    def update_vuln_ticket_description(description, row)
      description[:assets] += "\n#{get_assets(row)}"
      description
    end

    # Generates a final description string based on a Default-mode 
    # description hash.
    #
    #   - +description+ - The finished ticket hash to be converted.
    #
    # * *Returns* :
    #   - String containing ticket description text.
    #
    def print_default_ticket_description(description)
      ticket = "#{description[:header]}\n#{description[:references]}"
      ticket << "#{description[:solutions]}"
      ticket
    end

    # Generates a final description string based on an IP-mode 
    # description hash.
    #
    #   - +description+ - The finished ticket hash to be converted.
    #
    # * *Returns* :
    #   - String containing ticket description text.
    #
    def print_ip_ticket_description(description)
      ticket = ''
      description[:vulnerabilities].each { |v| ticket << "#{v}\n" } 
      ticket
    end

    # Generates a final description string based on a Vulnerability-mode 
    # description hash.
    #
    #   - +description+ - The finished ticket hash to be converted.
    #
    # * *Returns* :
    #   - String containing ticket description text.
    #
    def print_vuln_ticket_description(description)
      ticket = "#{description[:header]}\n#{description[:assets]}"
      ticket << "\n#{description[:references]}\n#{description[:solutions]}"
      ticket
    end

    # Generates the NXID. The NXID is a unique identifier used to find and update and/or close tickets.
    #
    # * *Args*    :
    #   - +nexpose_identifier_id+ -  Site/TAG ID the tickets are being generated for. Required for all? { |e|  } ticketing modes
    #   - +row+ -  Row from the generated Nexpose CSV report. Required for default ('D') mode.
    #   - +current_ip+ -  The IP address of that this ticket is for. Required for IP mode ('I') mode.
    #
    # * *Returns* :
    #   - NXID string.
    #
    def generate_nxid(nexpose_id, row)
      fail 'Row data is nil' if row.nil?

      case @ticketing_mode
        when 'D' then "#{nexpose_id}d#{row['asset_id']}d#{row['vulnerability_id']}"
        when 'I' then "#{nexpose_id}i#{row['ip_address']}"
        when 'V' then "#{nexpose_id}v#{row['vulnerability_id']}"
        else fail 'Ticketing mode not recognised.'
      end
    end
    
    # Formats the row data to be inserted into a 'D' or 'I' mode ticket description.
    #
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - String formatted with vulnerability data.
    #
    def get_vuln_info(row)
      ticket = get_vuln_header(row)
      ticket << get_discovery_info(row)
      ticket << get_references(row)
      ticket << "\n#{get_solutions(row)}"
      ticket.gsub("\n", "\n ")
    end

    # Generates the vulnerability header from the row data.
    #
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - String formatted with vulnerability data.
    #
    def get_vuln_header(row)
      ticket = "\n=============================="
      ticket << "\nVulnerability ID: #{row['vulnerability_id']}"
      ticket << "\nCVSS Score: #{row['cvss_score']}"
      ticket << "\n=============================="
      ticket
    end

    # Generates the ticket's title depending on the ticketing mode.
    #
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - String containing the ticket title.
    #
    def get_title(row, maximum=nil)
      title = case @ticketing_mode
          when 'D' then "#{row['ip_address']} => #{get_short_summary(row)}"
          when 'I' then "#{row['ip_address']} => Vulnerabilities"
          when 'V' then "Vulnerability: #{row['title']}"
          else fail 'Ticketing mode not recognised.'
        end
      return title if maximum == nil || title.length < maximum

      title = "#{title[0, 97]}..."
    end

    # Generates a short summary for a vulnerability.
    #
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - String containing a short summary of the vulnerability.
    #
    def get_short_summary(row)
      summary = row['solutions']
      delimiter = summary.to_s.index('|')
      return summary[summary.index(':')+1...delimiter].strip if delimiter
      summary.length <= 100 ? summary : summary[0...100]
    end

    # Formats the solutions for a vulnerability in a format suitable to be inserted into a ticket.
    #
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - String formatted with solution information.
    #
    def get_solutions(row)
      row['solutions'].to_s.gsub('|', "\n").gsub('~', "\n--\n")
    end

    def get_discovery_info(row)
      return '' if row['first_discovered'].to_s == ""
      info = "\nFirst Seen: #{row['first_discovered']}\n"
      info << "Last Seen: #{row['most_recently_discovered']}\n"
      info
    end

    # Formats the references for a vulnerability in a format suitable to be inserted into a ticket.
    #
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - String formatted with source and reference.
    #
    def get_references(row)
      return '' if row['references'].nil?
      references = "\nSources:\n"
      refs =  row['references'].split(', ')
      refs[MAX_NUM_REFS] = '...' if refs.count > MAX_NUM_REFS
      refs[0..MAX_NUM_REFS].each { |r| references << " - #{r}\n" }
      references
    end

    
    # Returns the assets for a vulnerability in a format suitable to be inserted into a ticket.
    #
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - String formatted with affected assets.
    #
    def get_assets(row)  
      status = row['comparison']
      header = "\n#{status || 'Affected' } Assets\n"

      assets = []
      row['assets'].to_s.split('~').each do |a|
        details = a.split('|')
        assets << " - #{details[1]} #{"\t(#{details[2]})" if !details[2].empty?}"
      end
      asset_list = assets.join("\n")
      "#{header}#{asset_list}"
    end

    # Returns the relevant row values for printing.
    #
    #   - +fields+ -  The fields which are relevant to the ticket.
    #   - +row+ -  CSV row containing vulnerability data.
    #
    # * *Returns* :
    #   - String formatted with relevant fields.
    #
    def get_field_info(fields, row)
      fields.map { |x| "#{x.sub("_", " ")}: #{row[x]}" }.join(", ")
    end
  end
end