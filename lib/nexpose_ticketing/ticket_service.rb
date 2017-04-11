module NexposeTicketing
#
# The Nexpose Ticketing service.
#
=begin

Copyright (C) 2014, Rapid7 LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

    * Neither the name of Rapid7 LLC nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=end

#
# WARNING! This code makes an SSL connection to the Nexpose server, but does NOT
#          verify the certificate at this time. This can be a security issue if
#          an attacker is able to man-in-the-middle the connection between the
#          Metasploit console and the Nexpose server. In the common case of
#          running Nexpose and Metasploit on the same host, this is a low risk.
#

#
# WARNING! This code is still rough and going through substantive changes. While
#          you can build tools using this library today, keep in mind that
#          method names and parameters may change in the future.
#
  class TicketService
    require 'csv'
    require 'yaml'
    require 'fileutils'
    require 'nexpose_ticketing/ticket_repository'
    require 'nexpose_ticketing'
    require 'nexpose_ticketing/nx_logger'
    require 'nexpose_ticketing/version'
    require 'nexpose_ticketing/store'

    TICKET_SERVICE_CONFIG_PATH =  File.join(File.dirname(__FILE__), '/config/ticket_service.config')
    LOGGER_FILE = File.join(File.dirname(__FILE__), '/logs/ticket_service.log')

    attr_accessor :helper_data, :nexpose_data, :options, :ticket_repository, :first_time

    def setup(helper_data)
      # Gets the Ticket Service configuration.
      service_data = begin
        YAML.load_file(TICKET_SERVICE_CONFIG_PATH)
      rescue ArgumentError => e
        raise "Could not parse YAML #{TICKET_SERVICE_CONFIG_PATH} : #{e.message}"
      end

      @helper_data = helper_data
      @nexpose_data = service_data[:nexpose_data]
      @options = service_data[:options]
      @options[:file_name] = @options[:file_name].to_s
      @options[:scan_mode] = get_scan_mode
      
      #Temporary - this should be refactored out e.g. to include DAGs
      @options[:tag_run] = @options[:scan_mode] == 'tag'

      file_name = @options["#{@options[:scan_mode]}_file_name".to_sym]
      @historical_file = File.join(File.dirname(__FILE__), file_name)

      # Sets logging up, if enabled.
      setup_logging(@options[:logging_enabled])


      mode_class = load_class 'mode', @options[:ticket_mode]
      @mode = mode_class.new(@options)

      @options[:query_suffix] = @mode.get_query_suffix

      helper_class = load_class 'helper', @helper_data[:helper_name]
      @helper = helper_class.new(@helper_data, @options, @mode)

      log_message("Creating ticketing repository with timeout value: #{@options[:timeout]}.")
      @ticket_repository = NexposeTicketing::TicketRepository.new(options)
      @ticket_repository.nexpose_login(@nexpose_data)

      solutions = get_solutions
      @mode.set_solution_store solutions
    end

    def load_class(type, name)
      name.gsub!(type.capitalize, '')
      path = "#{type}s/#{name}_#{type}.rb".downcase
      
      log_message("Loading #{type} dependency: #{path}.")
      begin 
        require_relative path
      rescue => e
        error = "#{type.capitalize} dependency '#{path}' could not be loaded."
        @log.error e.to_s
        @log.error error
        fail error
      end

      eval("#{name}#{type.capitalize}")
    end

    def setup_logging(enabled = false)
      helper_log = NexposeTicketing::NxLogger.instance
      helper_log.setup_logging(@options[:logging_enabled],
                               @options[:log_level],
                               @options[:log_console])

      return unless enabled
      require 'logger'
      directory = File.dirname(LOGGER_FILE)
      FileUtils.mkdir_p(directory) unless File.directory?(directory)
      @log = Logger.new(LOGGER_FILE, 'monthly')
      @log.level = Logger::INFO
      log_message('Logging enabled, starting service.')
    end

    # Logs a message if logging is enabled.
    def log_message(message)
      @log.info(message) if @options[:logging_enabled]
    end

    # Prepares all the local and nexpose historical data.
    def prepare_historical_data(ticket_repository, options)
      historical_scan_file = @historical_file

      file_site_histories = nil
      if File.exists?(historical_scan_file)
        log_message("Reading historical CSV file: #{historical_scan_file}.")
        file_site_histories = ticket_repository.read_last_scans(historical_scan_file)
      end

      file_site_histories
    end

    # Generates a full site(s) report ticket(s).
    def all_site_report(ticket_repository, options)
      group = "#{options[:scan_mode]}s"

      log_message("Generating full vulnerability report on user entered #{group}.")
      items_to_query = Array(options[group.to_sym])
      log_message("Generating full vulnerability report on the following #{group}: #{items_to_query.join(', ')}")
      
      items_to_query.each do |item|
        log_message("Running full vulnerability report on item #{item}")
        initial_scan_file = ticket_repository.generate_initial_scan_data(options,
                                                                         item)

        log_message('Preparing tickets.')
        nexpose_id = format_id(item)
        ticket_rate_limiter(initial_scan_file, 'create', nexpose_id)
        post_scan(item_id: item, generate_asset_list: true)
      end

      log_message('Finished processing all vulnerabilities.')
    end

    # There's possibly a new scan with new data.
    def delta_site_report(ticket_repository, options, scan_histories)
      # Compares the scan information from file && Nexpose.
      no_processing = true
      @latest_scans.each do |item_id, last_scan_id|
        prev_scan_id = scan_histories[item_id]

        # There's no entry in the file, so it's either a new item in Nexpose or a new item we have to monitor.
        if prev_scan_id.nil? || prev_scan_id == -1
          options[:nexpose_item] = item_id
          full_new_site_report(item_id, ticket_repository, options)
          options[:nexpose_item] = nil
          post_scan(item_id: item_id, generate_asset_list: true)
          no_processing = false
        # Site has been scanned since last seen according to the file.
        elsif prev_scan_id.to_s != @latest_scans[item_id].to_s
          delta_new_scan(item_id, options, scan_histories)
          post_scan item_id: item_id
          no_processing = false
        end
      end

      log_name = @options["#{@options[:scan_mode]}_file_name".to_sym]
      # Done processing, update the CSV to the latest scan info.
      if no_processing
        log_message("Nothing new to process, historical CSV file has not been updated: #{options[:file_name]}.") 
      else
        log_message("Done processing, historical CSV file has been updated: #{options[:file_name]}.")
      end
      no_processing
    end

    # There's a new site we haven't seen before.
    def full_new_site_report(nexpose_item, ticket_repository, options)
      log_message("New nexpose id: #{nexpose_item} detected. Generating report.")
      options[:scan_id] = 0

      initial_scan_file = ticket_repository.generate_initial_scan_data(options,
                                                                       nexpose_item)
      log_message('Preparing tickets.')

      nexpose_id = format_id(nexpose_item)
      ticket_rate_limiter(initial_scan_file, 'create', nexpose_id)
    end

    def ticket_rate_limiter_processor(ticket_batch, ticket_method, nexpose_item)
      #Just the header (no tickets).
      if ticket_batch.size == 1
        log_message('Received empty batch. Not sending tickets.')
        return
      end

      nexpose_item = format_id(nexpose_item)

      # Prep the batch of tickets
      log_message("Preparing to #{ticket_method} tickets.")
      tickets = @helper.send("prepare_#{ticket_method}_tickets", 
                             ticket_batch.join(''), 
                             nexpose_item)
      log_message("Parsed rows: #{ticket_batch.size}")

      # Send them off
      log_message('Sending tickets.')
      @helper.send("#{ticket_method}_tickets", tickets)
      log_message('Returning for next batch.')
    end

    def ticket_rate_limiter(query_results_file, ticket_method, nexpose_item)
      batch_size_max = @options[:batch_size]
      max_tickets = @options[:batch_ticket_limit]

      log_message("Batching tickets in sizes: #{@options[:batch_size]}")
      fields = @mode.get_matching_fields
      current_ids = Hash[*fields.collect { |k| [k, nil] }.flatten]

      # Start the batching
      query_results_file.rewind
      csv_header = query_results_file.readline
      batch = []
      individual_ticket = []
      ticket_count = 0
      prev_row = nil

      begin
        CSV.foreach(query_results_file, headers: csv_header) do |row|
          if prev_row.nil?
            # First row of a ticket
            prev_row = row
            ticket_count = ticket_count + 1
            individual_ticket = [row]
          elsif fields.any? { |k| prev_row[k].nil? || prev_row[k] != row[k] }
            # New ticket found
            prev_row = nil
            batch.concat individual_ticket

            if batch.count >= batch_size_max || ticket_count >= max_tickets
              ticket_rate_limiter_processor(batch, ticket_method, nexpose_item)

              ticket_count = 0
              batch.clear
              batch << csv_header
            end

            redo
          else
            # Another row for existing ticket
            individual_ticket << row
          end
        end
      ensure
        log_message('Finished reading report. Sending any remaining tickets and cleaning up file system.')

        # Finish adding to the batch
        batch.concat individual_ticket
        ticket_rate_limiter_processor(batch, ticket_method, nexpose_item)

        query_results_file.close
        query_results_file.unlink
      end 
    end

    def get_scan_mode
      return 'tag' unless @options[:tags].nil? || @options[:tags].empty?
      return 'site'
    end

    # Starts the Ticketing Service.
    def start
      # Checks if the csv historical file already exists and reads it, otherwise create it and assume first time run.
      scan_histories = prepare_historical_data(@ticket_repository, @options)


      # If we didn't specify a site || first time run (no scan history), then it gets all the vulnerabilities.
      @options[:initial_run] = full_scan_required?(scan_histories)

      if @options[:initial_run]
        full_scan
      else
        delta_scan(scan_histories)
      end

      @helper.finish
      log_message('Exiting ticket service.')
    end

    def get_solutions
      log_message('Retrieving solutions from Nexpose')
      store = Store.new
      return store if Store.store_exists?

      store.set_path(@ticket_repository.get_solution_data)

      log_message('Parsing and storing solutions.')
      store.fill_store

      log_message('Solution store created.')
      store
    end

    def full_scan
      log_message('Storing current scan state before obtaining all vulnerabilities.')
      @current_scan_state = ticket_repository.load_last_scans(@options)
      
      all_site_report(@ticket_repository, @options)

      #Generate historical CSV file after completing the fist query.
      log_message('Historical CSV file generated.')
    end

    def delta_scan(scan_histories)
      log_message('Obtaining last scan information.')
      @latest_scans = @ticket_repository.last_scans(@options)

      # Scan states can change during our processing. Store the state we are
      # about to process and move this to the historical file if we
      # successfully process.
      log_message('Calculated deltas, storing current scan state.')
      @current_scan_state = ticket_repository.load_last_scans(@options)

      # Only run if a scan has been ran ever in Nexpose.
      return if @latest_scans.empty?

      delta_site_report(@ticket_repository, @options, scan_histories)
      log_message('Historical CSV file updated.')
    end

    # Performs a delta scan
    def delta_new_scan(item_id, options, scan_histories)
      delta_func = "delta_#{options[:scan_mode]}_new_scan"
      self.send(delta_func, item_id, options, scan_histories)
    end

    # There's a new scan with possibly new vulnerabilities.
    def delta_site_new_scan(nexpose_item, options, file_site_histories, tag_id=nil)
      log_message("New scan detected for nexpose id: #{nexpose_item}. Generating report.")
      
      format_method = "format_#{options[:scan_mode]}_id"
      nexpose_id = self.send(format_method, tag_id || nexpose_item)

      log_message("Scan id for new scan: #{file_site_histories[nexpose_item]}.")

      if @mode.updates_supported?
        helper_method = 'update'
        old_vulns_mode = 'old_ticket'
      else
        helper_method = 'create'
        old_vulns_mode = 'old'
      end

      scan_options = { scan_id: file_site_histories[nexpose_item],
                       nexpose_item: nexpose_item,
                       severity: options[:severity],
                       ticket_mode: options[:ticket_mode],
                       riskScore: options[:riskScore],
                       vulnerabilityCategories: options[:vulnerabilityCategories],
                       tag_run: options[:tag_run],
                       tag: tag_id,
                       old_vulns_mode: old_vulns_mode }

      close_tickets = (options[:close_old_tickets_on_update] == 'Y')

      csv_files = @ticket_repository.generate_delta_csv(scan_options,
                                                        close_tickets)
      delta_scan_file = csv_files[:new_csv]

      log_message('Preparing tickets.')

      ticket_rate_limiter(delta_scan_file, helper_method, nexpose_id)
        
      return unless close_tickets

      old_vulns_file = csv_files[:old_csv]

      ticket_rate_limiter(old_vulns_file, 'close', nexpose_id)
    end

    def delta_tag_new_scan(nexpose_item, options, file_site_histories, tag_id=nil)
      # It's a tag run and something has changed (new/removed asset or new scan ID for an asset). To find out what, we must compare
      # All tag assets and their scan IDs. Firstly we fetch all the assets in the tags
      # in the configuration file and store them temporarily
      item_id = nexpose_item
      tag_assets_tmp_file = File.join(File.dirname(__FILE__), "/tag_assets/#{options[:tag_file_name]}_#{item_id}.tmp")
      tag_assets_historic_file = File.join(File.dirname(__FILE__), "/tag_assets/#{options[:tag_file_name]}_#{item_id}.csv")
      ticket_repository.generate_tag_asset_list(tags: item_id,
                              csv_file: tag_assets_tmp_file)
      new_tag_configuration = ticket_repository.read_tag_asset_list(tag_assets_tmp_file)
      historic_tag_config = ticket_repository.read_tag_asset_list(tag_assets_historic_file)
      #Compare the assets within the tags and their scan histories to find the ones we need to query
      changed_assets = Hash[*(historic_tag_config.to_a - new_tag_configuration.to_a).flatten]
      new_assets = Hash[*(new_tag_configuration.to_a - historic_tag_config.to_a).flatten]
      new_assets.delete_if {|asset_id, scan_id| historic_tag_config.has_key?(asset_id.to_s)}

      #all_assets_changed = new_assets.merge(changed_assets)
      changed_assets.each do |asset_id, scan_id|
        delta_site_new_scan(asset_id, options, changed_assets, item_id)
      end

      new_assets.each do |asset_id, scan_id|
        #Since no previous scan IDs - we generate a full report.
        options[:nexpose_item] = asset_id
        full_new_site_report(item_id, ticket_repository, options)
        options.delete(:nexpose_item)
      end

       #Update the historic file
      new_tag_asset_list = historic_tag_config.merge(new_tag_configuration)
      trimmed_csv = []
      trimmed_csv << 'asset_id, last_scan_id'
      new_tag_asset_list.each do |asset_id, last_scan_id|
        trimmed_csv << "#{asset_id},#{last_scan_id}"
      end
      ticket_repository.save_to_file(tag_assets_historic_file, trimmed_csv)
      File.delete(tag_assets_tmp_file)
    end

    # Methods to run after a scan
   def post_scan(**modifiers)
      self.send("post_#{@options[:scan_mode]}_scan", modifiers)
      scan_history = self.send("get_#{@options[:scan_mode]}_file_header")

      item_id = modifiers[:item_id]
      historic_data = nil
      if File.exists?(@historical_file)
        log_message("Updating historical CSV file: #{@historical_file}.")
        historic_data = []
        CSV.foreach(@historical_file, headers: true) { |r| historic_data << r }
      end

      updated_row = [@current_scan_state.find { |row| row[0].eql?(item_id) }]

      if historic_data.nil?
        log_message('No historical CSV file found. Generating.')
        scan_history.concat(updated_row)
      else
        index = historic_data.find_index { |id| id[0] == item_id }
        if index.nil?
          historic_data.concat(updated_row)
          historic_data.sort! { |x,y| x[0].to_i <=> y[0].to_i }
        else
          historic_data[index] = updated_row
          historic_data.flatten!
        end
        scan_history.concat(historic_data)
      end
      
      log_message('Updated historical CSV file for ' \
                  "#{@options[:scan_mode]}: #{item_id}.")
      @ticket_repository.save_to_file(@historical_file, scan_history)
    end

    def post_site_scan(**modifiers)
    end

    def post_tag_scan(**modifiers)
      return unless modifiers[:generate_asset_list]      
      file_name = "#{@options[:tag_file_name]}_#{modifiers[:item_id]}.csv"
      historic_file = File.join(File.dirname(__FILE__), 'tag_assets', file_name)

      log_message("Generating current tag asset file: #{historic_file}.")
      ticket_repository.generate_tag_asset_list(tags: modifiers[:item_id],
                                                csv_file: historic_file)
    end

    def get_site_file_header
      ['site_id,last_scan_id,finished']
    end

    def get_tag_file_header
      ['tag_id,last_scan_fingerprint']
    end

    # Formats the Nexpose item ID according to the asset grouping mode
    def format_id(item_id)
      self.send("format_#{options[:scan_mode]}_id", item_id)
    end

    def format_site_id(item_id)
      item_id
    end

    def format_tag_id(item_id)
      "T#{item_id}"
    end

    # Determines whether all assets must be scanned
    def full_scan_required?(histories)
      self.send("full_#{@options[:scan_mode]}_scan_required?", histories)
    end

    def full_site_scan_required?(scan_histories)
      is_full_run = false

      if @options[:sites].nil? || @options[:sites].empty?
        is_full_run = true
        
        all_site_details = @ticket_repository.all_site_details
        @options[:sites] = all_site_details.map { |s| s.id.to_s }
       
        log_message("List of sites is now <#{@options[:sites]}>")
      end

      is_full_run || scan_histories.nil?
    end

    def full_tag_scan_required?(scan_histories)
      if @options[:tags].nil? || @options[:tags].empty?
        fail 'No tags specified within the configuration.'  
      end
      return scan_histories.nil?
    end
  end
end
