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

    TICKET_SERVICE_CONFIG_PATH =  File.join(File.dirname(__FILE__), '/config/ticket_service.config')
    LOGGER_FILE = File.join(File.dirname(__FILE__), '/log/ticket_service.log')

    attr_accessor :helper_data, :nexpose_data, :options, :ticket_repository, :first_time, :nexpose_item_histories

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
      @options[:file_name] = "#{@options[:file_name]}"

      # Setups logging if enabled.
      setup_logging(@options[:logging_enabled])

      # Loads all the helpers.
      log_message('Loading helpers.')
      Dir[File.join(File.dirname(__FILE__), '/helpers/*.rb')].each do |file|
        log_message("Loading helper: #{file}")
        require_relative file
      end
      log_message("Ticket mode: #{@options[:ticket_mode]}.")

      log_message("Enabling helper: #{@helper_data[:helper_name]}.")
      @helper = eval(@helper_data[:helper_name]).new(@helper_data, @options)

      log_message("Creating ticketing repository with timeout value: #{@options[:timeout]}.")
      @ticket_repository = NexposeTicketing::TicketRepository.new(options)
      @ticket_repository.nexpose_login(@nexpose_data)
    end

    def setup_logging(enabled = false)
      if enabled
        require 'logger'
        directory = File.dirname(LOGGER_FILE)
        FileUtils.mkdir_p(directory) unless File.directory?(directory)
        @log = Logger.new(LOGGER_FILE, 'monthly')
        @log.level = Logger::INFO
        log_message('Logging enabled, starting service.')
      end
    end

    # Logs a message if logging is enabled.
    def log_message(message)
      @log.info(message) if @options[:logging_enabled]
    end

    # Prepares all the local and nexpose historical data.
    def prepare_historical_data(ticket_repository, options)
      (options[:tag_run]) ?
          historical_scan_file = File.join(File.dirname(__FILE__), "#{options[:tag_file_name]}") :
          historical_scan_file = File.join(File.dirname(__FILE__), "#{options[:file_name]}")

      if File.exists?(historical_scan_file)
        log_message("Reading historical CSV file: #{historical_scan_file}.")
        file_site_histories = ticket_repository.read_last_scans(historical_scan_file)
      else
        file_site_histories = nil
      end
      file_site_histories
    end

    # Generates a full site(s) report ticket(s).
    def all_site_report(ticket_repository, options, helper)
      if(options[:tag_run])
        log_message('Generating full vulnerability report on user entered tags.')
        items_to_query = Array(options[:tags])
        log_message("Generating full vulnerability report on the following tags: #{items_to_query}")
      else
        log_message('Generating full vulnerability report on user entered sites.')
        items_to_query =  Array(options[:sites])
        log_message("Generating full vulnerability report on the following sites: #{items_to_query.join(', ')}")
      end
      items_to_query.each { |item|
        log_message("Running full vulnerability report on item #{item}")
        all_vulns_file = ticket_repository.all_vulns(options, item)
        log_message('Preparing tickets.')
        ticket_rate_limiter(options, all_vulns_file, Proc.new { |ticket_batch| helper.prepare_create_tickets(ticket_batch, options[:tag_run] ? "T#{item}" : item) }, Proc.new { |tickets| helper.create_tickets(tickets) })
      }

      if(options[:tag_run])
        items_to_query. each { |item_id|
        tag_assets_historic_file = File.join(File.dirname(__FILE__), 'tag_assets', "#{options[:tag_file_name]}_#{item_id}.csv")
        ticket_repository.generate_tag_asset_list(tags: item_id,
                                csv_file: tag_assets_historic_file)
        }
      end
      log_message('Finished process all vulnerabilities.')
    end

    # There's possibly a new scan with new data.
    def delta_site_report(ticket_repository, options, helper, file_site_histories)
      # Compares the scan information from file && Nexpose.
      no_processing = true
      @nexpose_item_histories.each do |item_id, last_scan_id|
        # There's no entry in the file, so it's either a new item in Nexpose or a new item we have to monitor.
        if file_site_histories[item_id].nil? || file_site_histories[item_id] == -1
          full_new_site_report(item_id, ticket_repository, options, helper)
          if(options[:tag_run])
            tag_assets_historic_file = File.join(File.dirname(__FILE__), 'tag_assets', "#{options[:tag_file_name]}_#{item_id}.csv")
            ticket_repository.generate_tag_asset_list(tags: item_id,
                                                      csv_file: tag_assets_historic_file)
          end
          no_processing = false
          # Site has been scanned since last seen according to the file.
        elsif file_site_histories[item_id].to_s != nexpose_item_histories[item_id].to_s
          if(options[:tag_run])
            # It's a tag run and something has changed (new/removed asset or new scan ID for an asset). To find out what, we must compare
            # All tag assets and their scan IDs. Firstly we fetch all the assets in the tags
            # in the configuration file and store them temporarily
            tag_assets_tmp_file = File.join(File.dirname(__FILE__), "/tag_assets/#{options[:tag_file_name]}_#{item_id}.tmp")
            tag_assets_historic_file = File.join(File.dirname(__FILE__), "/tag_assets/#{options[:tag_file_name]}_#{item_id}.csv")
            ticket_repository.generate_tag_asset_list(tags: item_id,
                                    csv_file: tag_assets_tmp_file)
            new_tag_configuration = ticket_repository.read_tag_asset_list(tag_assets_tmp_file)
            historic_tag_configuration = ticket_repository.read_tag_asset_list(tag_assets_historic_file)
            #Compare the assets within the tags and their scan histories to find the ones we need to query
            changed_assets = Hash[*(historic_tag_configuration.to_a - new_tag_configuration.to_a).flatten]
            new_assets = Hash[*(new_tag_configuration.to_a - historic_tag_configuration.to_a).flatten]
            new_assets.delete_if {|asset_id, scan_id| historic_tag_configuration.has_key?(asset_id.to_s)}
            #all_assets_changed = new_assets.merge(changed_assets)
            changed_assets.each do |asset_id, scan_id|
              delta_site_new_scan(ticket_repository, asset_id, options, helper, changed_assets, item_id)
            end
            new_assets.each do |asset_id, scan_id|
              #Since no previous scan IDs - we generate a full report.
              options[:nexpose_item] = asset_id
              full_new_site_report(item_id, ticket_repository, options, helper)
              options.delete(:nexpose_item)
            end
          else
            delta_site_new_scan(ticket_repository, item_id, options, helper, file_site_histories)
          end
          #Update the historic file
          new_tag_asset_list = historic_tag_configuration.merge(new_tag_configuration)
          trimmed_csv = []
          trimmed_csv << 'asset_id, last_scan_id'
          new_tag_asset_list.each do |asset_id, last_scan_id|
            trimmed_csv << "#{asset_id},#{last_scan_id}"
          end
          ticket_repository.save_to_file(tag_assets_historic_file, trimmed_csv)
          File.delete(tag_assets_tmp_file)
          no_processing = false
        end
      end
      # Done processing, update the CSV to the latest scan info.
      log_message("Nothing new to process, updating historical CSV file #{options[:file_name]}.") if no_processing
      log_message("Done processing, updating historical CSV file #{options[:file_name]}.") unless no_processing
      no_processing
    end

    # There's a new site we haven't seen before.
    def full_new_site_report(nexpose_item, ticket_repository, options, helper)
      log_message("New nexpose id: #{nexpose_item} detected. Generating report.")
      new_item_vuln_file = ticket_repository.all_vulns(options, nexpose_item)
      log_message('Report generated, preparing tickets.')
      ticket_rate_limiter(options, new_item_vuln_file, Proc.new {|ticket_batch| helper.prepare_create_tickets(ticket_batch, options[:tag_run] ? "T#{nexpose_item}" : nexpose_item)}, Proc.new {|tickets| helper.create_tickets(tickets)})
    end

    # There's a new scan with possibly new vulnerabilities.
    def delta_site_new_scan(ticket_repository, nexpose_item, options, helper, file_site_histories, tag_id=nil)
      log_message("New scan detected for nexpose id: #{nexpose_item}. Generating report.")
      
      if options[:ticket_mode] == 'I' || options[:ticket_mode] == 'V'
        # I-mode and V-mode tickets require updating the tickets in the target system.
        log_message("Scan id for new scan: #{file_site_histories[nexpose_item]}.")
        all_scan_vuln_file = ticket_repository.all_vulns_since(scan_id: file_site_histories[nexpose_item],
                                                               nexpose_item: nexpose_item,
                                                               severity: options[:severity],
                                                               ticket_mode: options[:ticket_mode],
                                                               riskScore: options[:riskScore],
                                                               vulnerabilityCategories: options[:vulnerabilityCategories],
                                                               tag_run: options[:tag_run],
                                                               tag: tag_id)

        if helper.respond_to?('prepare_update_tickets') && helper.respond_to?('update_tickets')
          ticket_rate_limiter(options, all_scan_vuln_file, Proc.new {|ticket_batch| helper.prepare_update_tickets(ticket_batch, tag_id.nil? ? nexpose_item : "T#{tag_id}")}, Proc.new {|tickets| helper.update_tickets(tickets)})
        else
          log_message('Helper does not implement update methods')
          fail "Helper using 'I' or 'V' mode must implement prepare_updates and update_tickets"
        end

        if options[:close_old_tickets_on_update] == 'Y'
          tickets_to_close_file = ticket_repository.tickets_to_close(scan_id: file_site_histories[nexpose_item],
                                                                     nexpose_item: nexpose_item,
                                                                     severity: options[:severity],
                                                                     ticket_mode: options[:ticket_mode],
                                                                     riskScore: options[:riskScore],
                                                                     vulnerabilityCategories: options[:vulnerabilityCategories],
                                                                     tag_run: options[:tag_run],
                                                                     tag: tag_id)

          if helper.respond_to?('prepare_close_tickets') && helper.respond_to?('close_tickets')
            ticket_rate_limiter(options, tickets_to_close_file, Proc.new {|ticket_batch| helper.prepare_close_tickets(ticket_batch, tag_id.nil? ? nexpose_item : "T#{tag_id}")}, Proc.new {|tickets| helper.close_tickets(tickets)})
          else
            log_message('Helper does not implement close methods')
            fail 'Helper using \'I\' or \'V\' mode must implement prepare_close_tickets and close_tickets'
          end
        end
      else
        # D-mode tickets require creating new tickets and closing old tickets.
        new_scan_vuln_file = ticket_repository.new_vulns(scan_id: file_site_histories[nexpose_item],
                                                               nexpose_item: nexpose_item,
                                                               severity: options[:severity],
                                                               ticket_mode: options[:ticket_mode],
                                                               riskScore: options[:riskScore],
                                                               vulnerabilityCategories: options[:vulnerabilityCategories],
                                                               tag_run: options[:tag_run],
                                                               tag: tag_id)

        preparse = CSV.new(new_scan_vuln_file.path, headers: :first_row)
        empty_report = preparse.shift.nil?
        log_message("No new vulnerabilities found in new scan for site: #{nexpose_item}.") if empty_report
        log_message("New vulnerabilities found in new scan for site #{nexpose_item}, preparing tickets.") unless empty_report
        unless empty_report
          ticket_rate_limiter(options, new_scan_vuln_file, Proc.new {|ticket_batch| helper.prepare_create_tickets(ticket_batch, tag_id.nil? ? nexpose_item : "T#{tag_id}")}, Proc.new {|tickets| helper.create_tickets(tickets)})
        end
        
        if helper.respond_to?('prepare_close_tickets') && helper.respond_to?('close_tickets')
          old_scan_vuln_file = ticket_repository.old_vulns(scan_id: file_site_histories[nexpose_item],
                                                                 site_id: nexpose_item,
                                                                 severity: options[:severity],
                                                                 riskScore: options[:riskScore],
                                                                 vulnerabilityCategories: options[:vulnerabilityCategories],
                                                                 tag_run: options[:tag_run],
                                                                 tag: tag_id)

          preparse = CSV.new(old_scan_vuln_file.path, headers: :first_row, :skip_blanks => true)
          empty_report = preparse.shift.nil?
          log_message("No old (closed) vulnerabilities found in new scan for site: #{nexpose_item}.") if empty_report
          log_message("Old vulnerabilities found in new scan for site #{nexpose_item}, preparing closures.") unless empty_report
          unless empty_report
            ticket_rate_limiter(options, old_scan_vuln_file, Proc.new {|ticket_batch| helper.prepare_close_tickets(ticket_batch, tag_id.nil? ? nexpose_item : "T#{tag_id}")}, Proc.new {|tickets| helper.close_tickets(tickets)})
          end
        else
          # Create a log message but do not halt execution of the helper if ticket closing is not
          # supported to allow legacy code to execute normally.
          log_message('Helper does not implement close methods.')
        end
      end
    end


    def ticket_rate_limiter(options, query_results_file, ticket_prepare_method, ticket_send_method)
      batch_size_max = (options[:batch_size] + 1)
      log_message("Batching tickets in sizes: #{options[:batch_size]}")

      #Vulnerability mode is batched by vulnerability_id. The rest are batched by ip_address.
      if @options[:ticket_mode] == 'V'
        batching_field = 'vulnerability_id'
      else
        batching_field = 'ip_address'
      end

      # Start the batching
      query_results_file.rewind
      csv_header = query_results_file.readline
      ticket_batch = []
      current_batching_value = -1
      current_csv_row = nil

      begin
        IO.foreach(query_results_file) do |line|
          ticket_batch << line

          CSV.parse(line.chomp, headers: csv_header)  do |row|
            if current_batching_value == -1
              current_batching_value = row[batching_field.to_s]  unless row[batching_field.to_s] == 'current_batching_value'
            end
            current_csv_row = row unless row[batching_field.to_s] == 'current_batching_value'
          end

          if ticket_batch.size >= batch_size_max
            #Batch target reached. Make sure we  end with a complete IP address set (all tickets for a single IP in this batch)
            if(current_batching_value != current_csv_row[batching_field.to_s])
              log_message('Batch size reached. Sending tickets.')

              #Move the mismatching line to the next batch
              line_holder = ticket_batch.pop
              ticket_rate_limiter_processor(ticket_batch, ticket_prepare_method, ticket_send_method)
              # Cleanup for the next batch
              ticket_batch.clear
              ticket_batch << csv_header
              ticket_batch << line_holder
              current_batching_value = -1
            end
          end
        end
      ensure
        log_message('Finished reading report. Sending any remaining tickets and cleaning up file system.')
        ticket_rate_limiter_processor(ticket_batch, ticket_prepare_method, ticket_send_method)
        query_results_file.close
        query_results_file.unlink
      end
    end

    def ticket_rate_limiter_processor(ticket_batch, ticket_prepare_method, ticket_send_method)
      #Just the header (no tickets).
      if ticket_batch.size == 1
        log_message('Received empty batch. Not sending tickets.')
        return
      end

      # Prep the batch of tickets
      log_message('Creating tickets.')
      tickets = ticket_prepare_method.call(ticket_batch.join(''))
      log_message("Generated tickets: #{ticket_batch.size}")
      # Sent them off
      log_message('Sending tickets.')
      ticket_send_method.call(tickets)
      log_message('Returning for next batch.')
    end


    # Starts the Ticketing Service.
    def start
      #Decide if this is a tag run (tags always override sites as the API does not allow for the combination of the two)
      @options[:tag_run] = !@options[:tags].nil? && !@options[:tags].empty?

      # Checks if the csv historical file already exists && reads it, otherwise create it && assume first time run.
      file_site_histories = prepare_historical_data(@ticket_repository, @options)
      historical_scan_file = File.join(File.dirname(__FILE__), "#{@options[:file_name]}")
      historical_tag_file = File.join(File.dirname(__FILE__), "#{@options[:tag_file_name]}")

      # If we didn't specify a site || first time run (no scan history), then it gets all the vulnerabilities.
      if (((@options[:sites].nil? || @options[:sites].empty? || file_site_histories.nil?) && !@options[:tag_run]) || (@options[:tag_run] && file_site_histories.nil?))
      log_message('Storing current scan state before obtaining all vulnerabilities.')
        current_scan_state = ticket_repository.load_last_scans(@options)

        if (options[:sites].nil? || options[:sites].empty?) && (!@options[:tag_run])
          log_message('No site(s) specified, generating for all sites.')
          @ticket_repository.all_site_details.each { |site|  (@options[:sites] ||= []) << site.id.to_s }
          log_message("List of sites is now <#{@options[:sites]}>")
        end

        all_site_report(@ticket_repository, @options, @helper)

        #Generate historical CSV file after completing the fist query.
        log_message('No historical CSV file found. Generating.')
        @options[:tag_run] ?
            @ticket_repository.save_to_file(historical_tag_file, current_scan_state) :
            @ticket_repository.save_to_file(historical_scan_file, current_scan_state)
        log_message('Historical CSV file generated.')
      else
        log_message('Obtaining last scan information.')
        @nexpose_item_histories = @ticket_repository.last_scans(@options)

        # Scan states can change during our processing. Store the state we are
        # about to process and move this to the historical file if we
        # successfully process.
        log_message('Calculated deltas, storing current scan state.')
        current_scan_state = ticket_repository.load_last_scans(options)

        # Only run if a scan has been ran ever in Nexpose.
        unless @nexpose_item_histories.empty?
          delta_site_report(@ticket_repository, @options, @helper, file_site_histories)
          # Processing completed successfully. Update historical scan file.
          @options[:tag_run] ?
              @ticket_repository.save_to_file(historical_tag_file, current_scan_state) :
              @ticket_repository.save_to_file(historical_scan_file, current_scan_state)
        end
      end
      log_message('Exiting ticket service.')
    end
  end
end
