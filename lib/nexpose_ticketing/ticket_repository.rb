module NexposeTicketing
  # Repository class that creates and returns generated reports.
  class TicketRepository
    require 'csv'
    require 'nexpose'
    require 'nexpose_ticketing/queries'
    require 'nexpose_ticketing/report_helper'

    @timeout = 10800

    def initialize(options = nil)
      @timeout = options[:timeout]
    end

    def nexpose_login(nexpose_data)
      @nsc = Nexpose::Connection.new(nexpose_data[:nxconsole], nexpose_data[:nxuser], nexpose_data[:nxpasswd])
      @nsc.login
      #After login, create the report helper
      @report_helper = NexposeReportHelper::ReportOps.new(@nsc, @timeout)
    end

    # Returns an array of all sites in the users environment.
    #
    # * *Returns* :
    #   - An array of Nexpose::SiteSummary objects.
    #
    def all_site_details
      @nsc.sites
    end

    # Reads a nexpose identifier (tag ID, site ID etc) scan history from disk.
    #
    # * *Args*    :
    #   - +csv_file_name+ -  CSV File name.
    #
    # * *Returns* :
    #   - A hash with site_ids => last_scan_id
    #
    def read_last_scans(csv_file_name)
      file_identifier_histories = Hash.new(-1)
      CSV.foreach(csv_file_name, headers: true) do |row|
          file_identifier_histories[row[0]] = row[1]
      end
      file_identifier_histories
    end

    # Saves the last scan info to disk.
    #
    # * *Args*    :
    #   - +csv_file_name+ -  CSV File name.
    #
    def save_last_scans(csv_file_name, options = {}, saved_file = nil)
      current_scan_state = load_last_scans(options)
      save_to_file(csv_file_name, current_scan_state, saved_file)
    end

    # Loads the last scan info to memory.
    #
    # * *Args*    :
    #   - +csv_file_name+ -  CSV File name.
    #
    def load_last_scans(options = {}, report_config = Nexpose::AdhocReportConfig.new(nil, 'sql'))
      report_config.add_filter('version', '1.2.0')
      sites = Array(options[:sites])
      tags = Array(options[:tags])
      if(options[:tag_run])
        report_config.add_filter('query', Queries.last_tag_scans)
        tags.each do |tag|
          report_config.add_filter('tag', tag)
        end
      else
        report_config.add_filter('query', Queries.last_scans)
      end

      report_output = report_config.generate(@nsc, @timeout)
      csv_output = CSV.parse(report_output.chomp,  headers: :first_row)

      #We only care about sites we are monitoring.
      trimmed_csv = []
      if(options[:tag_run])
        trimmed_csv << 'tag_id, last_scan_fingerprint'
        current_tag_id = nil
        tag_finger_print = ''
        csv_output.each  do |row|
          if (tags.include? row[0].to_s) && (row[0].to_i != current_tag_id)
            if(current_tag_id.nil?)
              #Initial run
              current_tag_id = row[0].to_i
            else
              #New tag ID, finish off the old fingerprint and start on the new one
              trimmed_csv << CSV::Row.new('tag_id, last_scan_fingerprint'.split(','), "#{current_tag_id},#{Digest::MD5::hexdigest(tag_finger_print)}".split(','))
              tag_finger_print.clear
              current_tag_id = row[0].to_i
            end
          end

          if(current_tag_id == row[0].to_i)
            #yield current_tag_id, row[1].to_s, row[2].to_s if block_given?
            tag_finger_print << row[1].to_s
            tag_finger_print << row[2].to_s
          end
        end
        unless tag_finger_print.empty?
          trimmed_csv << CSV::Row.new('tag_id, last_scan_fingerprint'.split(','), "#{current_tag_id},#{Digest::MD5::hexdigest(tag_finger_print)}".split(','))
        end
      else
        trimmed_csv << report_output.lines.first
        csv_output.each  do |row|
          if sites.include? row[0].to_s
            trimmed_csv << row
          end
        end
      end
      trimmed_csv
    end

    # Parses user-configured vulnerability filter categories and returns aforementioned categories in a
    # format used by the Nexpose::AdhocReportConfig class.
    #
    # * *Args*    :
    #   - +options+ -  A Hash with site(s), reported_scan_id and severity level.
    #
    # * *Returns* :
    #   - Returns String @vulnerability_categories
    #
    def createVulnerabilityFilter(options = {})
      @vulnerability_categories = nil
      if options.has_key?(:vulnerabilityCategories)
        if not options[:vulnerabilityCategories].nil? and not options[:vulnerabilityCategories].empty?
          @vulnerability_categories = options[:vulnerabilityCategories].strip.split(',').map {|category| "include:#{category}"}.join(',')
        end
      end
      @vulnerability_categories
    end

    def read_tag_asset_list(cvs_file_name)
      file_identifier_histories = Hash.new(-1)
      CSV.foreach(cvs_file_name, headers: true) do |row|
        file_identifier_histories[row[0]] = row[1]
      end
      file_identifier_histories
    end

    def generate_tag_asset_list(options = {}, report_config = Nexpose::AdhocReportConfig.new(nil, 'sql'))
      report_config.add_filter('version', '1.2.0')
      tags = Array(options[:tags])
        report_config.add_filter('query', Queries.last_tag_scans)
      tags.each do |tag|
        report_config.add_filter('tag', tag)
      end

      report_output = report_config.generate(@nsc, @timeout)
      csv_output = CSV.parse(report_output.chomp,  headers: :first_row)
      trimmed_csv = []
      trimmed_csv << 'asset_id, last_scan_id'
      current_tag_id = nil
      csv_output.each  do |row|
        if (tags.include? row[0].to_s) && (row[0].to_i != current_tag_id)
          if(current_tag_id.nil?)
            #Initial run
            current_tag_id = row[0].to_i
          else
            #New tag ID, finish off the previous tag asset list and start on the new one
            save_to_file(options[:csv_file], trimmed_csv)
            current_tag_id = row[0].to_i
            trimmed_csv = []
          end
        end

        if(current_tag_id == row[0].to_i)
          trimmed_csv << "#{row[1].to_s},#{row[2].to_s}"
        end
      end
      save_to_file(options[:csv_file], trimmed_csv) if trimmed_csv.any?
    end

    # Saves CSV scan information to disk
    #
    # * *Args*    :
    #   - +csv_file_name+ -  CSV File name.
    #
    def save_to_file(csv_file_name, trimmed_csv, saved_file = nil)
      saved_file.open(csv_file_name, 'w') { |file| file.puts(trimmed_csv) } unless saved_file.nil?
      if saved_file.nil?
        dir = File.dirname(csv_file_name)
        unless File.directory?(dir)
          FileUtils.mkdir_p(dir)
        end
        File.open(csv_file_name, 'w') { |file| file.puts(trimmed_csv) }
      end
    end

    # Gets the last scan information from nexpose sans the CSV headers.
    #
    # * *Returns* :
    #   - A hash with nexpose_ids (site ID or tag ID) => last_scan_id
    #
    def last_scans(options = {})
      nexpose_ids= Hash.new(-1)
      trimmed_csv = load_last_scans(options)
      trimmed_csv.drop(1).each  do |row|
        nexpose_ids[row[0]] = row[1]
      end
      nexpose_ids
    end

    # Gets all the vulnerabilities for a new site or fresh install.
    #
    # * *Args*    :
    #   - +options+ -  A Hash with user configuration information.
    #   - +nexpose_item_override+ - Override for user-configured tag/site options
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def all_vulns(options = {}, nexpose_item_override = nil)
      report_config =  @report_helper.generate_sql_report_config()
      severity = options[:severity].nil? ? 0 : options[:severity]
      report_config.add_filter('version', '1.2.0')
      if options[:ticket_mode] == 'V'
        report_config.add_filter('query', Queries.all_new_vulns_by_vuln_id(options))
      else
        report_config.add_filter('query', Queries.all_new_vulns(options))
      end

      if nexpose_item_override.nil?
        if(options[:tag_run])
          nexpose_items = Array(options[:tags])
        else
          nexpose_items = Array(options[:sites])
        end
      else
        nexpose_items = Array(nexpose_item_override)
      end

      if options[:tag_run]
        unless nexpose_items.nil? || nexpose_items.empty?
          nexpose_items.each do |tag_id|
            report_config.add_filter('tag', tag_id)
          end
        end
      else
        unless nexpose_items.nil? || nexpose_items.empty?
          nexpose_items.each do |site_id|
            report_config.add_filter('site', site_id)
          end
        end
      end

      report_config.add_filter('vuln-severity', severity)

      vuln_filter_cats = createVulnerabilityFilter(options)

      if not vuln_filter_cats.nil? and not vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end

    # Gets the new vulns from base scan reported_scan_id and the newest / latest scan from a site.
    #
    # * *Args*    :
    #   - +options+ -  A Hash with user configuration information.
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def new_vulns(options = {})
      report_config =  @report_helper.generate_sql_report_config()
      nexpose_item = options[:nexpose_item]
      reported_scan_id = options[:scan_id]
      fail 'Nexpose item cannot be null or empty' if nexpose_item.nil? || reported_scan_id.nil?
      severity = options[:severity].nil? ? 0 : options[:severity]
      report_config.add_filter('version', '1.2.0')
      if options[:ticket_mode] == 'V'
        report_config.add_filter('query', Queries.new_vulns_by_vuln_id_since_scan(options))
      else
        report_config.add_filter('query', Queries.new_vulns_since_scan(options))
      end

      if(options[:tag_run])
        report_config.add_filter('tag', options[:tag])
      else
        report_config.add_filter('site', nexpose_item)
      end

      report_config.add_filter('vuln-severity', severity)

      vuln_filter_cats = createVulnerabilityFilter(options)

      if not vuln_filter_cats.nil? and not vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end
    
    # Gets the old vulns from base scan reported_scan_id and the newest / latest scan from a site.
    #
    # * *Args*    :
    #   - +options+ -  A Hash with user configuration information.
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def old_vulns(options = {})
      report_config =  @report_helper.generate_sql_report_config()
      nexpose_item = options[:nexpose_item]
      reported_scan_id = options[:scan_id]
      fail 'Nexpose item cannot be null or empty' if nexpose_item.nil? || reported_scan_id.nil?
      severity = options[:severity].nil? ? 0 : options[:severity]
      report_config.add_filter('version', '1.2.0')
      report_config.add_filter('query', Queries.old_vulns_since_scan(options))

      if(options[:tag_run])
        report_config.add_filter('tag', options[:tag])
      else
        report_config.add_filter('site', nexpose_item)
      end

      report_config.add_filter('vuln-severity', severity)

      vuln_filter_cats = createVulnerabilityFilter(options)

      if not vuln_filter_cats.nil? and not vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end

    # Gets information on possible tickets to close based on only having old vulns/IPs and no new/same ones.
    # Based on IP address (for 'I' mode) or vuln ID ('V' mode).
    #
    # * *Args*    :
    #   - +options+ -  A Hash with user configuration information.
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |comparison|
    #
    def tickets_to_close(options = {})
      report_config =  @report_helper.generate_sql_report_config()
      nexpose_item = options[:nexpose_item]
      reported_scan_id = options[:scan_id]
      fail 'Nexpose item cannot be null or empty' if nexpose_item.nil? || reported_scan_id.nil?
      severity = options[:severity].nil? ? 0 : options[:severity]
      report_config.add_filter('version', '1.2.0')
      if options[:ticket_mode] == 'V'
        report_config.add_filter('query', Queries.old_tickets_by_vuln_id(options))
      else
      report_config.add_filter('query', Queries.old_tickets_by_ip(options))
      end

      if(options[:tag_run])
        report_config.add_filter('tag', options[:tag])
      else
        report_config.add_filter('site', nexpose_item)
      end 

      report_config.add_filter('vuln-severity', severity)

      vuln_filter_cats = createVulnerabilityFilter(options)

      if not vuln_filter_cats.nil? and not vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end


    # Gets all vulns from base scan reported_scan_id and the newest / latest scan from a site. This is
    # used for IP-based issue updating. Includes the baseline comparision value ('Old','New', or 'Same').
    #
    # * *Args*    :
    #   - +options+ -  A Hash with user configuration information.
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix| |comparison| 
    #
    def all_vulns_since(options = {})
      report_config =  @report_helper.generate_sql_report_config()
      nexpose_item = options[:nexpose_item]
      reported_scan_id = options[:scan_id]
      fail 'Nexpose item cannot be null or empty' if nexpose_item.nil? || reported_scan_id.nil?
      severity = options[:severity].nil? ? 0 : options[:severity]
      report_config.add_filter('version', '1.2.0')
      if options[:ticket_mode] == 'V'
        report_config.add_filter('query', Queries.all_vulns_by_vuln_id_since_scan(options))
      else
        report_config.add_filter('query', Queries.all_vulns_since_scan(options))
      end

      if(options[:tag_run])
        report_config.add_filter('tag', options[:tag])
      else
        report_config.add_filter('site', nexpose_item)
      end
      report_config.add_filter('vuln-severity', severity)

      vuln_filter_cats = createVulnerabilityFilter(options)

      if not vuln_filter_cats.nil? and not vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end
  end
end
