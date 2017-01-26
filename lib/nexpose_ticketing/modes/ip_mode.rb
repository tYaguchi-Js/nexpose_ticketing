require_relative './base_mode.rb'

class IPMode < BaseMode

  # Initializes the mode
  def initialize(options)
    super(options)
  end

  # Returns the fields used to identify individual tickets
  def get_matching_fields
    ['ip_address']
  end

  # Returns the ticket's title
  def get_title(row)
    truncate_title "#{row['ip_address']} => Vulnerabilities"
  end

  # Generates a unique identifier for a ticket
  def get_nxid(nexpose_id, row)
    "#{nexpose_id}i#{row['ip_address']}"
  end

  # Returns the base ticket description object
  def get_description(nexpose_id, row)
    description = { nxid: "NXID: #{get_nxid(nexpose_id, row)}" }
    status = row['comparison']
    description[:ticket_status] = status
    header = "++ #{status} Vulnerabilities ++\n" if !status.nil?
    description[:vulnerabilities] = [ header.to_s + get_vuln_info(row) ]
    description
  end

  # Updates the ticket description based on row data
  def update_description(description, row)
    header = ""
    if description[:ticket_status] != row['comparison']
      header = "++ #{row['comparison']} Vulnerabilities ++\n"
      description[:ticket_status] = row['comparison']
    end

    description[:vulnerabilities] << "#{header}#{get_vuln_info(row)}"
    description
  end
  
  # Converts the ticket description object into a formatted string
  def print_description(description)
    finalize_description(description[:vulnerabilities].join("\n"), 
                         description[:nxid])
  end
end
