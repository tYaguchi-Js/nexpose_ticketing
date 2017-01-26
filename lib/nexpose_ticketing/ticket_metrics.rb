module NexposeTicketing
  class TicketMetrics
    attr_accessor :ticket_counts

    #Create the specific metric collecting methods
    @@ticket_counts = {}
    [:created, :updated, :closed].each do |action|
      @@ticket_counts[action] = 0
      define_method(action) do |increment=nil|
        @@ticket_counts[action] += increment || 1
      end

      define_method("get_#{action}") do
        @@ticket_counts[action]
      end
    end

    def initialize
      @start_time = nil
      @log = NexposeTicketing::NxLogger.instance
    end

    def start
      return if @start_time != nil
      @start_time = Time.now
    end

    def finish
      return if @start_time == nil  
      @time_taken = Time.at(Time.now - @start_time).utc.strftime("%H:%M:%S")
      @start_time = nil

      @log.log_message("Ticket processing took #{@time_taken} to complete.")
      @@ticket_counts.keys.each do |action|
        @log.log_message("Metrics: #{@@ticket_counts[action]} tickets were #{action}.")
      end
    end
  end
end
