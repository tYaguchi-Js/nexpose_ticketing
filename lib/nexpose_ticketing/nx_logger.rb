require 'fileutils'
require 'json'
require 'net/http'
require 'singleton'

module NexposeTicketing
  class NxLogger
    include Singleton
    attr_accessor :options, :statistic_key, :product, :logger_file
    LOG_PATH = "./logs/rapid7_%s.log"
    KEY_FORMAT = "external.integration.%s"
    PRODUCT_FORMAT = "%s_%s"

    DEFAULT_LOG = 'integration'
    PRODUCT_RANGE = 3..30
    KEY_RANGE = 3..15

    ENDPOINT = '/data/external/statistic/'

    def initialize()
      @logger_file = get_log_path product
      setup_logging(true, 'info')
    end

    def setup_statistics_collection(vendor, product_name, gem_version)
      #Remove illegal characters
      vendor.to_s.gsub!('-', '_')
      product_name.to_s.gsub!('-', '_')

      begin
        @statistic_key = get_statistic_key vendor
        @product = get_product product_name, gem_version
      rescue => e
        #Continue
      end
    end

    def setup_logging(enabled, log_level = nil)
      unless enabled || @log.nil?
        log_message('Logging disabled.')
        return
      end

      @logger_file = get_log_path product

      require 'logger'
      directory = File.dirname(@logger_file)
      FileUtils.mkdir_p(directory) unless File.directory?(directory)
      io = IO.for_fd(IO.sysopen(@logger_file, 'a'))
      io.autoclose = false
      io.sync = true
      @log = Logger.new(io, 'weekly')
      @log.level = if log_level.casecmp('info') == 0 
                     Logger::INFO 
                   else
                     Logger::DEBUG
                   end
      log_message("Logging enabled at level <#{log_level}>")
    end

    # Logs an info message
    def log_message(message)
      @log.info(message) unless @log.nil?
    end

    # Logs a debug message
    def log_debug_message(message)
      @log.debug(message) unless @log.nil?
    end

    # Logs an error message
    def log_error_message(message)
      @log.error(message) unless @log.nil?
    end

    # Logs a warn message
    def log_warn_message(message)
      @log.warn(message) unless @log.nil?
    end

    def log_stat_message(message)
    end

    def get_log_path(product)
      product.downcase! unless product.nil?
      File.join(File.dirname(__FILE__), LOG_PATH % (product || DEFAULT_LOG))
    end

    def get_statistic_key(vendor)
      if vendor.nil? || vendor.length < KEY_RANGE.min
        log_stat_message("Vendor length is below minimum of <#{KEY_RANGE}>")
        return nil
      end

      KEY_FORMAT % vendor[0...KEY_RANGE.max].downcase
    end

    def get_product(product, version)
      return nil if (product.nil? || version.nil?)
      product = (PRODUCT_FORMAT % [product, version])[0...PRODUCT_RANGE.max]

      if product.length < PRODUCT_RANGE.min
        log_stat_message("Product length below minimum <#{PRODUCT_RANGE.min}>.")
        return nil
      end
      product.downcase
    end

    def generate_payload(statistic_value='')
      payload = {'statistic-key' => @statistic_key,
                 'statistic-value' => statistic_value,
                 'product' => @product}
      JSON.generate(payload)
    end

    def send(nexpose_address, nexpose_port, session_id, payload)
      header = {'Content-Type' => 'application/json',
                'nexposeCCSessionID' => session_id,
                'Cookie' => "nexposeCCSessionID=#{session_id}"}
      req = Net::HTTP::Put.new(ENDPOINT, header)
      req.body = payload
      http_instance = Net::HTTP.new(nexpose_address, nexpose_port)
      http_instance.use_ssl = true
      http_instance.verify_mode = OpenSSL::SSL::VERIFY_NONE
      response = http_instance.start { |http| http.request(req) }
      log_stat_message "Received code #{response.code} from Nexpose console."
      log_stat_message "Received message #{response.msg} from Nexpose console."
      log_stat_message 'Finished sending statistics data to Nexpose.'
      response.code
    end

    def on_connect(nexpose_address, nexpose_port, session_id, value)
      log_stat_message 'Sending statistics data to Nexpose'

      if @product.nil? || @statistic_key.nil?
        log_stat_message('Invalid product name and/or statistics key.')
        log_stat_message('Statistics collection not enabled.')
        return
      end
      
      begin
        payload = generate_payload value
        send(nexpose_address, nexpose_port, session_id, payload)
      rescue => e
        #Let the program continue
      end
    end

  end
end