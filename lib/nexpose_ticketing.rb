require 'nexpose_ticketing/ticket_service'
# Main nexpose ticketing module, helper options
# should be passed as arguments to start.
module NexposeTicketing
  def self.start(args)
    ts = NexposeTicketing::TicketService.new
    ts.setup(args)
    ts.start
  end
end
