require 'fileutils'
require 'json'
require 'net/http'
require 'singleton'

module NexposeTicketing
  class NxLogger
    include Singleton
    LOG_PATH = '../logs/rapid7_%s.log'
    KEY_FORMAT = "external.integration.%s"
    PRODUCT_FORMAT = "%s_%s"

    DEFAULT_LOG = 'integration'
    PRODUCT_RANGE = 4..30
    KEY_RANGE = 3..15

    ENDPOINT = '/data/external/statistic/'

    def initialize()
      create_calls
      @logger_file = get_log_path @product
      setup_logging(true, 'info')
    end

    def setup_statistics_collection(vendor, product_name, gem_version)
      begin
        @statistic_key = get_statistic_key vendor
        @product = get_product product_name, gem_version
      rescue => e
        #Continue
      end
    end

    def setup_logging(enabled, log_level = 'info', stdout=false)
      @stdout = stdout

      log_message('Logging disabled.') unless enabled || @log.nil?
      @enabled = enabled
      return unless @enabled

      @logger_file = get_log_path @product

      require 'logger'
      directory = File.dirname(@logger_file)
      FileUtils.mkdir_p(directory) unless File.directory?(directory)
      io = IO.for_fd(IO.sysopen(@logger_file, 'a'), 'a')
      io.autoclose = false
      io.sync = true
      @log = Logger.new(io, 'weekly')
      @log.level = if log_level.to_s.casecmp('info') == 0 
                     Logger::INFO 
                   else
                     Logger::DEBUG
                   end
      log_message("Logging enabled at level <#{log_level}>")
    end

    def create_calls
      levels = [:info, :debug, :error, :warn]
      levels.each do |level|
        method_name = 
        define_singleton_method("log_#{level.to_s}_message") do |message|
          puts message if @stdout
          @log.send(level, message) unless !@enabled || @log.nil?
        end
      end
    end

    def log_message(message)
      log_info_message message
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

      vendor.gsub!('-', '_')
      vendor.slice! vendor.rindex('_') until vendor.count('_') <= 1

      vendor.delete! "^A-Za-z0-9\_"

      KEY_FORMAT % vendor[0...KEY_RANGE.max].downcase
    end

    def get_product(product, version)
      return nil if ((product.nil? || product.empty?) || 
                     (version.nil? || version.empty?))

      product.gsub!('-', '_')
      product.slice! product.rindex('_') until product.count('_') <= 1

      product.delete! "^A-Za-z0-9\_"
      version.delete! "^A-Za-z0-9\.\-"

      product = (PRODUCT_FORMAT % [product, version])[0...PRODUCT_RANGE.max]

      product.slice! product.rindex(/[A-Z0-9]/i)+1..-1

      if product.length < PRODUCT_RANGE.min
        log_stat_message("Product length below minimum <#{PRODUCT_RANGE.min}>.")
        return nil
      end
      product.downcase
    end

    def generate_payload(statistic_value='')
      product_name, separator, version = @product.to_s.rpartition('_')
      payload_value = {'version' => version}.to_json

      payload = {'statistic-key' => @statistic_key.to_s,
                 'statistic-value' => payload_value,
                 'product' => product_name}
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

    #Used by net library for debugging 
    def <<(value)
      log_debug_message(value)
    end

  end
end