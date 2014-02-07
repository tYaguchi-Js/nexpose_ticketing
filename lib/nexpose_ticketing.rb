require 'nexpose_ticketing/ticket_service'
module NexposeTicketing
  def self.start(args)
    ts = NexposeTicketing::TicketService.new
    ts.setup(args)
    ts.start
  end
end