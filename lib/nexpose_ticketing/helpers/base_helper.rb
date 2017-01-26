require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'csv'
require 'nexpose_ticketing/nx_logger'
require 'nexpose_ticketing/version'
require_relative '../ticket_metrics'

class BaseHelper
  attr_accessor :service_data, :options

  def initialize(service_data, options, mode)
    @service_data = service_data
    @options = options
    @log = NexposeTicketing::NxLogger.instance
    @metrics = NexposeTicketing::TicketMetrics.new

    load_dependencies
    @mode_helper = mode
  end

  # Load the mode helper specified in the config
  def load_dependencies  
    file = "#{@options[:ticket_mode]}_mode.rb".downcase
    path = File.join(File.dirname(__FILE__), "../modes/#{file}")

    @log.log_message("Loading #{@options[:ticket_mode]} mode dependencies.")
    begin 
      require_relative path
    rescue => e
      error = "Ticket mode dependency '#{file}' could not be loaded."
      @log.log_error_message e.to_s
      @log.log_error_message error
      fail error
    end 
  end

  # Performs any necessary clean-up
  def finish
    @metrics.finish
  end
end
