require 'erb'
require 'yaml'
require 'fileutils'
require 'symmetric-encryption'

class ConfigParser
  ENCRYPTED_FORMAT = '<%%= SymmetricEncryption.try_decrypt "%s" %%>'
  PLACEHOLDER = '<absolute/path/to/filename>'
  # The environment to use, defined within the encryption config
  STANZA = 'production'
  # The line width of the YAML file before line-wrapping occurs
  WIDTH = 120

  # Encrypts a configuration file and returns the unencrypted hash.
  def self.get_config(config_path, enc_path=nil)
    # Try to load a path from the provided config
    custom_enc_path = get_enc_directory(config_path)
    enc_path = custom_enc_path unless custom_enc_path.nil?

    enc_path = File.expand_path(enc_path, __FILE__)
    config_path = File.expand_path(config_path)


    generate_keys(enc_path, config_path)
    encrypt_config(enc_path, config_path)
    decrypt_config(enc_path, config_path)
  end

  # Writes the YAML to file with custom formatting options
  def self.save_config(config_details, config_path)
    yaml = config_details.to_yaml(line_width: WIDTH)
    File.open(config_path, 'w') {|f| f.write yaml }
  end

  def self.encrypt_field(value)
    encrypted_value = SymmetricEncryption.encrypt value
    ENCRYPTED_FORMAT % encrypted_value
  end

  # Retrieves the custom directory of the encryption config
  def self.get_enc_directory(config_path)
    settings = YAML.load_file(config_path)
    return nil if settings[:encryption_options].nil?

    enc_dir = settings[:encryption_options][:directory]
    return nil if (enc_dir.nil? || enc_dir == '')

    File.expand_path(enc_dir, __FILE__)
  end

  # Generates the RSA key, associated files and directories.
  def self.generate_keys(enc_path, config_path)
    settings = YAML.load_file(enc_path)
    key = settings[STANZA]['private_rsa_key']

    # Recognise an existing key
    return unless (key.nil? || key == '')

    # Generate a new RSA key and store the details
    new_rsa_key = SymmetricEncryption::KeyEncryptionKey.generate
    settings[STANZA]['private_rsa_key'] = new_rsa_key
    save_config(settings, enc_path)

    # Populate the placeholder values within the config
    populate_ciphers(enc_path, config_path)

    # Need to create a folder (specified by the user) to store the key files
    dir = File.dirname(settings[STANZA]['ciphers'].first['key_filename'])

    begin
      unless File.directory?(dir) || PLACEHOLDER.include?(dir)
        puts "Creating folder: #{dir}"
        FileUtils::mkdir_p dir
      end
    rescue Exception => e
      msg = "Unable to create the folders used to store encryption details.\n"\
            'Please ensure the user has permissions to create folders in the ' \
            "path specified in the  encryption config: #{enc_path}\n"
      handle_error(msg, e)
    end

    SymmetricEncryption.generate_symmetric_key_files(enc_path, STANZA)
  end

  # Replace placeholder values for the key and iv file paths,
  # placing them in the config folder by default.
  def self.populate_ciphers(enc_path, config_path)
    settings = YAML.load_file(enc_path)
    ciphers = settings[STANZA]['ciphers'].first
    config_folder = File.dirname(config_path)
    config_name = File.basename(config_path, File.extname(config_path))

    %w(key iv).each do |file|
      label = "#{file}_filename"
      file_path = ciphers[label]
      next unless file_path.include? PLACEHOLDER

      filename = ".#{config_name}.#{file}"
      ciphers[label] = File.join(config_folder, filename)
    end

    save_config(settings, enc_path)
  end

  def self.encrypt_config(enc_path, config_path)
    SymmetricEncryption.load!(enc_path, STANZA)

    # Read the config in as an array of strings
    f = File.open(config_path)
    config_lines = f.readlines
    f.close

    # Define the regex that can find relevant fields
    regex = /^(?<label>\s*:?\w*(passw|pwd|user|usr)\w*:?\s)(?<value>.*)$/

    # Line by line, write the line to file, encrypting sensitive fields
    File.open(config_path, 'w+') do |f|
      config_lines.each do |l|
        matches = l.match(regex)

        # Encrypt fields with username/password labels that are in plaintext
        unless matches.nil? || matches['value'].include?('SymmetricEncryption')
          l = "#{matches['label']}#{encrypt_field(matches['value'])}"
        end

        f.puts l
      end
    end
  end

  # Returns a hash containing the decrypted details from a config file.
  def self.decrypt_config(enc_path, config_path)
    SymmetricEncryption.load!(enc_path, STANZA)
    return YAML.load(ERB.new(File.new(config_path).read).result)
  end

  def self.handle_error(message, error)
    puts message
    raise error
  end
end
