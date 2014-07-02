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
      @ticket_repository = NexposeTicketing::TicketRepository.new
      @ticket_repository.nexpose_login(@nexpose_data)
      @first_time = false
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
        log_message('No historical CSV file found. Generating.')
        ticket_repository.save_last_scans(historical_scan_file)
        log_message('Historical CSV file generated.')
        file_site_histories = ticket_repository.read_last_scans(historical_scan_file)
        @first_time = true
      end
      file_site_histories
    end

    # Generates a full site(s) report ticket(s).
    def all_site_report(ticket_repository, options, helper,
        historical_scan_file = File.join(File.dirname(__FILE__), "#{options[:file_name]}"))
      log_message('First time run, generating full vulnerability report.') if @first_time
      log_message('No site(s) specified, generating full vulnerability report.') if options[:sites].empty?
      all_delta_vulns = ticket_repository.all_vulns(severity: options[:severity])
      log_message('Preparing tickets.')
      tickets = helper.prepare_create_tickets(all_delta_vulns)
      helper.create_tickets(tickets)
      log_message("Done processing, updating historical CSV file #{historical_scan_file}.")
      ticket_repository.save_last_scans(historical_scan_file)
      log_message('Done updating historical CSV file, service shutting down.')
    end

    # There's possibly a new scan with new data.
    def delta_site_report(ticket_repository, options, helper, file_site_histories,
          historical_scan_file = File.join(File.dirname(__FILE__), "#{options[:file_name]}"))
      # Compares the Scan information from the File && Nexpose.
      no_processing = true
      @nexpose_site_histories.each do |site_id, scan_id|
        # There's no entry in the file, so it's a new site in Nexpose.
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
      ticket_repository.save_last_scans(historical_scan_file)
      log_message('Done updating historical CSV file, service shutting down.')
      no_processing
    end

    # There's a new site we haven't seen before.
    def full_new_site_report(site_id, ticket_repository, options, helper)
      log_message("New site id: #{site_id} detected. Generating report.")
      new_site_vuln = ticket_repository.all_vulns(sites: [site_id], severity: options[:severity])
      log_message('Report generated, preparing tickets.')
      ticket = helper.prepare_create_tickets(new_site_vuln)
      helper.create_tickets(ticket)
    end

    # There's a new scan with possibly new vulnerabilities.
    def delta_site_new_scan(ticket_repository, site_id, options, helper, file_site_histories)
      log_message("New scan detected for site: #{site_id}. Generating report.")
      
      if options[:ticket_mode] == 'I'
        # I-mode tickets require updating the tickets in the target system.
        log_message("Scan id for new scan: #{file_site_histories[site_id]}.")
        all_scan_vuln = ticket_repository.all_vulns_sites(scan_id: file_site_histories[site_id], 
                                                          site_id: site_id,
                                                          severity: options[:severity])
        if helper.respond_to?("prepare_update_tickets") && helper.respond_to?("update_tickets")
          tickets = helper.prepare_update_tickets(all_scan_vuln)
          helper.update_tickets(tickets)
        else
          log_message("Helper does not implement update methods")
          fail "Helper using 'I' mode must implement prepare_updates and update_tickets"
        end
      else
        # D-mode tickets require creating new tickets and closing old tickets.
        new_scan_vuln = ticket_repository.new_vulns_sites(scan_id: file_site_histories[site_id], site_id: site_id,
                                                          severity: options[:severity])
        preparse = CSV.new(new_scan_vuln.chomp, headers: :first_row)
        empty_report = preparse.shift.nil?
        log_message("No new vulnerabilities found in new scan for site: #{site_id}.") if empty_report
        log_message("New vulnerabilities found in new scan for site #{site_id}, preparing tickets.") unless empty_report
        unless empty_report
          tickets = helper.prepare_create_tickets(new_scan_vuln)
          helper.create_tickets(tickets)
        end
        
        if helper.respond_to?("prepare_close_tickets") && helper.respond_to?("close_tickets")
          old_scan_vuln = ticket_repository.old_vulns_sites(scan_id: file_site_histories[site_id], site_id: site_id,
                                                            severity: options[:severity])
          preparse = CSV.new(old_scan_vuln.chomp, headers: :first_row)
          empty_report = preparse.shift.nil?
          log_message("No old (closed) vulnerabilities found in new scan for site: #{site_id}.") if empty_report
          log_message("Old vulnerabilities found in new scan for site #{site_id}, preparing closures.") unless empty_report
          unless empty_report
            tickets = helper.prepare_close_tickets(old_scan_vuln)
            helper.close_tickets(tickets)
          end
        else
          # Create a log message but do not halt execution of the helper if ticket closeing is not 
          # supported to allow legacy code to execute normally.
          log_message("Helper does not impelment close methods.")
        end
      end
    end

    # Starts the Ticketing Service.
    def start
      # Checks if the csv historical file already exists && reads it, otherwise create it && assume first time run.
      file_site_histories = prepare_historical_data(@ticket_repository, @options)
      # If we didn't specify a site || first time run, then it gets all the vulnerabilities.
      if @options[:sites].empty? || @first_time
        all_site_report(@ticket_repository, @options, @helper)
      else
        log_message('Obtaining last scan information.')
        @nexpose_site_histories = @ticket_repository.last_scans
        # Only run if a scan has been ran ever in Nexpose.
        unless @nexpose_site_histories.empty?
          delta_site_report(@ticket_repository, @options, @helper, file_site_histories)
        end
      end
    end
  end
end
