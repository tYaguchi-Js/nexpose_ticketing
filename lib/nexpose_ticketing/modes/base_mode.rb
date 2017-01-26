require 'nexpose_ticketing/nx_logger'

class BaseMode 

  # Initializes the mode
  def initialize(options)
    @options = options
    @log = NexposeTicketing::NxLogger.instance
  end

  # True if this mode supports ticket updates
  def updates_supported?
    true
  end

  # Returns the fields used to identify individual tickets
  def get_matching_fields
    ['']
  end

  # Returns the ticket's title
  def get_title(row)
    "#{nil} => #{nil}"
  end

  # Generates a unique identifier for a ticket
  def get_nxid(nexpose_id, row)
    "#{nil}c#{nil}"
  end

  # Returns the base ticket description object
  def get_description(nexpose_id, row)
    description
  end

  # Updates the ticket description based on row data
  def update_description(description, row)
    description
  end
  
  # Converts the ticket description object into a formatted string
  def print_description(description)
    ''
  end

  # Cuts the title down to size specified in config, if necessary
  def truncate_title(title)
    return title if title.length <= @options[:max_title_length]
    "#{title[0, @options[:max_title_length]-3]}..."
  end

  # Returns the suffix used for query method names 
  def get_query_suffix
    '_by_ip'
  end

  def load_queries
    file_name = "#{self.class.to_s.downcase}_queries.rb"
    file_path = File.join(File.dirname(__FILE__), "../queries/#{file_name}")
    @queries = []

    @queries << YAML.load_file(file_path)
  end

  # Generates a final description string based on a description hash.
  #
  #   - +ticket_desc+ - The ticket description to be formatted.
  #   - +nxid+ - The NXID to be appended to the ticket.
  #
  # * *Returns* :
  #   - String containing ticket description text.
  #
  def finalize_description(ticket_desc, nxid)
    nxid_line = "\n\n\n#{nxid}"
    
    #If the ticket is too long, truncate it to fit the NXID
    max_len = @options[:max_ticket_length]
    if max_len > 0 and (ticket_desc + nxid_line).length > max_len
      #Leave space for newline characters, nxid and ellipsis (...)
      ticket_desc = ticket_desc[0...max_len - (nxid_line.length+5)]
      ticket_desc << "\n...\n"
    end

    "#{ticket_desc}#{nxid_line}"
  end
  
  # Formats the row data to be inserted into a 'D' or 'I' mode ticket description.
  #
  #   - +row+ -  CSV row containing vulnerability data.
  #
  # * *Returns* :
  #   - String formatted with vulnerability data.
  #
  def get_vuln_info(row)
    ticket = get_header(row)
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
  def get_header(row)
    ticket = "\n=============================="
    ticket << "\nVulnerability ID: #{row['vulnerability_id']}"
    ticket << "\nNexpose ID: #{row['vuln_nexpose_id']}"
    ticket << "\nCVSS Score: #{row['cvss_score']}"
    ticket << "\n=============================="
  end

  # Generates a short summary for a vulnerability.
  #
  #   - +row+ -  CSV row containing vulnerability data.
  #
  # * *Returns* :
  #   - String containing a short summary of the vulnerability.
  #
  def get_short_summary(row)
    summary = row['solutions'].to_s
    delimiter = summary.index('|')
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
    num_refs = @options[:max_num_refs]
    return '' if row['references'].nil? || num_refs == 0
    
    refs =  row['references'].split(', ')[0..num_refs]
    refs[num_refs] = '...' if refs.count > num_refs
    "\nSources:\n#{refs.map { |r| " - #{r}" }.join("\n")}\n"
  end

  
  # Returns the assets for a vulnerability in a format suitable to be inserted into a ticket.
  #
  #   - +row+ -  CSV row containing vulnerability data.
  #
  # * *Returns* :
  #   - String formatted with affected assets.
  #
  def get_assets(row)
    assets = "\n#{row['comparison'] || 'Affected' } Assets\n"

    row['assets'].to_s.split('~').each do |a|
      asset = a.split('|')
      assets << " - #{asset[1]} #{"\t(#{asset[2]})" if !asset[2].empty?}\n"
    end
    assets
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
    fields.map { |x| "#{x.gsub("_", " ")}: #{row[x]}" }.join(", ")
  end

  # Catch-all method when a unknown method is called
  def method_missing(name, *args)
    @log.log_message("Method #{name} not implemented for #{@options[:ticket_mode]} mode.")
  end
end
