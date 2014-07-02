module NexposeTicketing
  class NXLogger
    TICKET_SERVICE_CONFIG_PATH =  File.join(File.dirname(__FILE__), '/config/ticket_service.config')
    LOGGER_FILE = File.join(File.dirname(__FILE__), '/log/ticket_helper.log')
    
    attr_accessor :options
    
    def initialize
      service_data = begin
        YAML.load_file(TICKET_SERVICE_CONFIG_PATH)
      rescue ArgumentError => e
        raise "Could not parse YAML #{TICKET_SERVICE_CONFIG_PATH} : #{e.message}"
      end
      
      @options = service_data[:options]
      setup_logging(@options[:logging_enabled])
    end 
    
    def setup_logging(enabled = false)
      if enabled
        require 'logger'
        directory = File.dirname(LOGGER_FILE)
        FileUtils.mkdir_p(directory) unless File.directory?(directory)
        @log = Logger.new(LOGGER_FILE, 'monthly')
        @log.level = Logger::INFO
        log_message('Logging enabled for helper.')
      end
    end

    # Logs a message if logging is enabled.
    def log_message(message)
      @log.info(message) if @options[:logging_enabled]
    end
  end
end
