require_relative './base_mode.rb'

class DefaultMode < BaseMode

  # Initializes the mode
  def initialize(options)
    super(options)
  end

  # True if this mode supports ticket updates
  def updates_supported?
    false
  end

  # Returns the fields used to identify individual tickets
  def get_matching_fields
    %w(ip_address vulnerability_id)
  end

  # Returns the ticket's title
  def get_title(row)
    truncate_title "#{row['ip_address']} => #{get_short_summary(row)}"
  end

  # Generates a unique identifier for a ticket
  def get_nxid(nexpose_id, row)
    "#{nexpose_id}d#{row['asset_id']}d#{row['vulnerability_id']}"
  end

  # Returns the base ticket description object
  def get_description(nexpose_id, row)
    description = { nxid: "NXID: #{get_nxid(nexpose_id, row)}" }
    fields = %w(header references solutions)
    fields.each { |f| description[f.intern] = self.send("get_#{f}", row) }
    description[:header] << get_discovery_info(row)
    description
  end

  # Updates the ticket description based on row data
  def update_description(description, row)
    description
  end
  
  # Converts the ticket description object into a formatted string
  def print_description(description)
    fields = [:header, :references, :solutions].map { |f| description[f] }
    finalize_description(fields.join("\n"), 
                         description[:nxid])
  end
end