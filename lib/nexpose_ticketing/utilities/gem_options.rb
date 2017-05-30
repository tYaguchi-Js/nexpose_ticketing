require 'optparse'

class GemOptions

  @parser

  def self.create_parser
    @parser = OptionParser.new
    self
  end

  # How the gem is used e.g 'nexpose ticketing jira [options]'
  def self.with_banner(gem_usage_string)
    @parser.banner = "Usage: #{gem_usage_string} [options]"
    @parser.separator ''
    self
  end

  # Header for options list
  def self.with_options
    @parser.separator 'Options:'
    self
  end

  # Creates banner and options
  def self.with_banner_and_options(gem_usage_string)
    with_banner(gem_usage_string)
    with_options
    self
  end

  # For setting encryption switch. Can be set to work with two configurations
  # Config_paths is an array
  def self.with_configuration_encryption(config_paths, enc_path = nil)
    @parser.on('-e',
            '--encrypt_config',
            'Encrypt the configuration file(s) without running the gem') do |e|
      ConfigParser.get_config(config_paths.first, enc_path) unless enc_path.nil?
      ConfigParser.get_config(config_paths.last)
      puts "\nConfiguration File(s) Encrypted"
      exit
    end
    self
  end

  def self.with_help
    @parser.on_tail('-h', '--help', 'Show this message') do |h|
      puts @parser
      exit
    end
    self
  end

  def self.with_version(gem, version)
    @parser.on_tail('--version', 'Version Information') do |v|
      puts "#{gem} #{version}"
      exit
    end
    self
  end

  def self.with_help_and_version(gem, version)
    with_help
    with_version(gem, version)
    self
  end

  # Method to allow integrations to create own options, with both short and long
  # switches and description.
  # Handler is the block to run when option is called.
  def self.with_other_option(short_switch, long_switch, description, &handler)
    @parser.on("-#{short_switch}", "--#{long_switch}", description) do |opt|
      handler.call
    end
  end

  # Method to allow integrations to create own options, with only one size of
  # switch and description.
  # '-' for short switches and '--' for long switches is required.
  # Handler is the block to run when option is called.
  def self.with_single_switch_option(identifier, switch, description, &handler)
    @parser.on("#{identifier}#{switch}", description) do |opt|
      handler.call
    end
  end

  # Parses the options to make them available
  def self.parse
    @parser.parse!
  end
end
