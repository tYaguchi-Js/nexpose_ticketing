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

    attr_accessor :helper_data, :nexpose_data, :options, :ticket_repository, :first_time, :nexpose_site_histories

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
    def prepare_historical_data(ticket_repository, options,
        historical_scan_file = File.join(File.dirname(__FILE__), "#{options[:file_name]}"))
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

      sites_to_query = Array.new
      if options[:sites].empty?
        log_message('No site(s) specified, generating full vulnerability report.')
        @ticket_repository.all_site_details.each { |site| sites_to_query << site.id }
      else
        log_message('Generating full vulnerability report on user entered sites.')
        sites_to_query =  Array(options[:sites])
      end

      log_message("Generating full vulnerability report on the following sites: #{sites_to_query.join(', ')}")

      sites_to_query.each { |site|
        log_message("Running full vulnerability report on site #{site}")
        all_vulns_file = ticket_repository.all_vulns(options, site)
        log_message('Preparing tickets.')
        ticket_rate_limiter(options, all_vulns_file, Proc.new { |ticket_batch| helper.prepare_create_tickets(ticket_batch) }, Proc.new { |tickets| helper.create_tickets(tickets) })
      }
      log_message('Finished process all vulnerabilities.')
    end

    # There's possibly a new scan with new data.
    def delta_site_report(ticket_repository, options, helper, file_site_histories)
      # Compares the Scan information from the File && Nexpose.
      no_processing = true
      @nexpose_site_histories.each do |site_id, scan_id|
        # There's no entry in the file, so it's either a new site in Nexpose or a new site we have to monitor.
        if file_site_histories[site_id].nil? || file_site_histories[site_id] == -1
          full_new_site_report(site_id, ticket_repository, options, helper)
          no_processing = false
          # Site has been scanned since last seen according to the file.
        elsif file_site_histories[site_id].to_i < nexpose_site_histories[site_id]
          delta_site_new_scan(ticket_repository, site_id, options, helper, file_site_histories)
          no_processing = false
        end
      end
      # Done processing, update the CSV to the latest scan info.
      log_message("Nothing new to process, updating historical CSV file #{options[:file_name]}.") if no_processing
      log_message("Done processing, updating historical CSV file #{options[:file_name]}.") unless no_processing
      no_processing
    end

    # There's a new site we haven't seen before.
    def full_new_site_report(site_id, ticket_repository, options, helper)
      log_message("New site id: #{site_id} detected. Generating report.")
      new_site_vuln_file = ticket_repository.all_vulns(sites: [site_id], severity: options[:severity])
      log_message('Report generated, preparing tickets.')
      ticket_rate_limiter(options, new_site_vuln_file, Proc.new {|ticket_batch| helper.prepare_create_tickets(ticket_batch)}, Proc.new {|tickets| helper.create_tickets(tickets)})
    end

    # There's a new scan with possibly new vulnerabilities.
    def delta_site_new_scan(ticket_repository, site_id, options, helper, file_site_histories)
      log_message("New scan detected for site: #{site_id}. Generating report.")
      
      if options[:ticket_mode] == 'I'
        # I-mode tickets require updating the tickets in the target system.
        log_message("Scan id for new scan: #{file_site_histories[site_id]}.")
        all_scan_vuln_file = ticket_repository.all_vulns_sites(scan_id: file_site_histories[site_id],
                                                          site_id: site_id,
                                                          severity: options[:severity])
        if helper.respond_to?("prepare_update_tickets") && helper.respond_to?("update_tickets")
          ticket_rate_limiter(options, all_scan_vuln_file, Proc.new {|ticket_batch| helper.prepare_update_tickets(ticket_batch)}, Proc.new {|tickets| helper.update_tickets(tickets)})
        else
          log_message("Helper does not implement update methods")
          fail "Helper using 'I' mode must implement prepare_updates and update_tickets"
        end
      else
        # D-mode tickets require creating new tickets and closing old tickets.
        new_scan_vuln_file = ticket_repository.new_vulns_sites(scan_id: file_site_histories[site_id], site_id: site_id,
                                                          severity: options[:severity])
        preparse = CSV.new(new_scan_vuln_file.path, headers: :first_row)
        empty_report = preparse.shift.nil?
        log_message("No new vulnerabilities found in new scan for site: #{site_id}.") if empty_report
        log_message("New vulnerabilities found in new scan for site #{site_id}, preparing tickets.") unless empty_report
        unless empty_report
          ticket_rate_limiter(options, new_scan_vuln_file, Proc.new {|ticket_batch| helper.prepare_create_tickets(ticket_batch)}, Proc.new {|tickets| helper.create_tickets(tickets)})
        end
        
        if helper.respond_to?("prepare_close_tickets") && helper.respond_to?("close_tickets")
          old_scan_vuln_file = ticket_repository.old_vulns_sites(scan_id: file_site_histories[site_id], site_id: site_id,
                                                            severity: options[:severity])
          preparse = CSV.new(old_scan_vuln_file.path, headers: :first_row, :skip_blanks => true)
          empty_report = preparse.shift.nil?
          log_message("No old (closed) vulnerabilities found in new scan for site: #{site_id}.") if empty_report
          log_message("Old vulnerabilities found in new scan for site #{site_id}, preparing closures.") unless empty_report
          unless empty_report
            ticket_rate_limiter(options, old_scan_vuln_file, Proc.new {|ticket_batch| helper.prepare_close_tickets(ticket_batch)}, Proc.new {|tickets| helper.close_tickets(tickets)})
          end
        else
          # Create a log message but do not halt execution of the helper if ticket closeing is not 
          # supported to allow legacy code to execute normally.
          log_message('Helper does not impelment close methods.')
        end
      end
    end

    def ticket_rate_limiter(options, query_results_file, ticket_prepare_method, ticket_send_method)
      batch_size_max = (options[:batch_size] + 1)
      log_message("Batching tickets in sizes: #{options[:batch_size]}")

      # Start the batching
      query_results_file.rewind
      csv_header = query_results_file.readline
      ticket_batch = []
      current_ip = -1
      current_csv_row = nil

      begin
        IO.foreach(query_results_file) do |line|
          ticket_batch << line

          CSV.parse(line.chomp, headers: csv_header)  do |row|
            if current_ip == -1
              current_ip = row['ip_address']  unless row['ip_address'] == 'ip_address'
            end
            current_csv_row = row unless row['ip_address'] == 'ip_address'
          end

          if ticket_batch.size >= batch_size_max
            #Batch target reached. Make sure we  end with a complete IP address set (all tickets for a single IP in this batch)
            if(current_ip != current_csv_row['ip_address'])
              log_message('Batch size reached. Sending tickets.')

              #Move the mismatching line to the next batch
              line_holder = ticket_batch.pop
              ticket_rate_limiter_processor(ticket_batch, ticket_prepare_method, ticket_send_method)
              # Cleanup for the next batch
              ticket_batch.clear
              ticket_batch << csv_header
              ticket_batch << line_holder
              current_ip = -1
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
      # Checks if the csv historical file already exists && reads it, otherwise create it && assume first time run.
      file_site_histories = prepare_historical_data(@ticket_repository, @options)
      historical_scan_file = File.join(File.dirname(__FILE__), "#{@options[:file_name]}")
      # If we didn't specify a site || first time run (no scan history), then it gets all the vulnerabilities.
      if @options[:sites].empty? || file_site_histories.nil?
        log_message('Storing current scan state before obtaining all vulnerabilities.')
        current_scan_state = ticket_repository.load_last_scans(options)

        all_site_report(@ticket_repository, @options, @helper)

        #Generate historical CSV file after completing the fist query.
        log_message('No historical CSV file found. Generating.')
        @ticket_repository.save_scans_to_file(historical_scan_file, current_scan_state)
        log_message('Historical CSV file generated.')
      else
        log_message('Obtaining last scan information.')
        @nexpose_site_histories = @ticket_repository.last_scans(@options)

        # Scan states can change during our processing. Store the state we are
        # about to process and move this to the historical_scan_file if we
        # successfully process.
        log_message('Calculated deltas, storing current scan state.')
        current_scan_state = ticket_repository.load_last_scans(options)

        # Only run if a scan has been ran ever in Nexpose.
        unless @nexpose_site_histories.empty?
          delta_site_report(@ticket_repository, @options, @helper, file_site_histories)
          # Processing completed successfully. Update historical scan file.
          @ticket_repository.save_scans_to_file(historical_scan_file, current_scan_state)
        end
      end
      log_message('Exiting ticket service.')
    end
  end
end
