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
    def all_site_details()
      @nsc.sites
    end

    # Reads the site scan history from disk.
    #
    # * *Args*    :
    #   - +csv_file_name+ -  CSV File name.
    #
    # * *Returns* :
    #   - A hash with site_ids => last_scan_id
    #
    def read_last_scans(csv_file_name)
      file_site_histories = Hash.new(-1)
      CSV.foreach(csv_file_name, headers: true) do |row|
        file_site_histories[row['site_id']] = row['last_scan_id']
      end
      file_site_histories
    end

    # Saves the last scan info to disk.
    #
    # * *Args*    :
    #   - +csv_file_name+ -  CSV File name.
    #
    def save_last_scans(csv_file_name, options = {}, saved_file = nil)
      current_scan_state = load_last_scans(options)
      save_scans_to_file(csv_file_name, current_scan_state, saved_file)
    end

    # Loads the last scan info to memory.
    #
    # * *Args*    :
    #   - +csv_file_name+ -  CSV File name.
    #
    def load_last_scans(options = {}, report_config = Nexpose::AdhocReportConfig.new(nil, 'sql'))
      sites = Array(options[:sites])
      report_config.add_filter('version', '1.2.0')
      report_config.add_filter('query', Queries.last_scans)

      report_output = report_config.generate(@nsc, @timeout)
      csv_output = CSV.parse(report_output.chomp,  headers: :first_row)

      #We only care about sites we are monitoring.
      trimmed_csv = []
      trimmed_csv << report_output.lines.first
      csv_output.each  do |row|
        if sites.include? row[0].to_s
          trimmed_csv << row
        end
      end
      trimmed_csv
    end

    # Saves CSV scan information to disk
    #
    # * *Args*    :
    #   - +csv_file_name+ -  CSV File name.
    #
    def save_scans_to_file(csv_file_name, trimmed_csv, saved_file = nil)
      saved_file.open(csv_file_name, 'w') { |file| file.puts(trimmed_csv) } unless saved_file.nil?
      if saved_file.nil?
        File.open(csv_file_name, 'w') { |file| file.puts(trimmed_csv) }
      end
    end

    # Gets the last scan information from nexpose sans the CSV headers.
    #
    # * *Returns* :
    #   - A hash with site_ids => last_scan_id
    #
    def last_scans(options = {})
      nexpose_sites = Hash.new(-1)
      trimmed_csv = load_last_scans(options)
      trimmed_csv.drop(1).each  do |row|
        nexpose_sites[row['site_id']] = row['last_scan_id'].to_i
      end
      nexpose_sites
    end

    # Gets all the vulnerabilities for a new site or fresh install.
    #
    # * *Args*    :
    #   - +site_options+ -  A Hash with site(s) and severity level.
    #   - +site_to_query+ - Override for user-configured site options
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def all_vulns(options = {}, site_override = nil)
      if site_override.nil?
        sites = Array(options[:sites])
      else
        sites = Array(site_override)
      end
      report_config =  @report_helper.generate_sql_report_config()
      severity = options[:severity].nil? ? 0 : options[:severity]
      report_config.add_filter('version', '1.2.0')
      if options[:ticket_mode] == 'V'
        report_config.add_filter('query', Queries.all_new_vulns_by_vuln_id(options))
      else
          report_config.add_filter('query', Queries.all_new_vulns(options))
      end
      unless sites.nil? || sites.empty?
        Array(sites).each do |site_id|
          report_config.add_filter('site', site_id)
        end
      end
      report_config.add_filter('vuln-severity', severity)

      vuln_filter_cats = createVulnerabilityFilter(options)
      vuln_filer_tags = createTagFilters(options)

      if not vuln_filter_cats.nil? and not vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      if not vuln_filer_tags.nil? and not vuln_filer_tags.empty?
        vuln_filer_tags.map {|tag| report_config.add_filter('tag', tag.id) }
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end

    # Gets the new vulns from base scan reported_scan_id and the newest / latest scan from a site.
    #
    # * *Args*    :
    #   - +site_options+ -  A Hash with site(s), reported_scan_id and severity level.
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def new_vulns_sites(site_options = {})
      report_config =  @report_helper.generate_sql_report_config()
      site = site_options[:site_id]
      reported_scan_id = site_options[:scan_id]
      fail 'Site cannot be null or empty' if site.nil? || reported_scan_id.nil?
      severity = site_options[:severity].nil? ? 0 : site_options[:severity]
      report_config.add_filter('version', '1.2.0')
      if site_options[:ticket_mode] == 'V'
        report_config.add_filter('query', Queries.new_vulns_by_vuln_id_since_scan(site_options))
      else
        report_config.add_filter('query', Queries.new_vulns_since_scan(site_options))
      end
      report_config.add_filter('site', site)
      report_config.add_filter('vuln-severity', severity)

      vuln_filter_cats = createVulnerabilityFilter(site_options)
      vuln_filer_tags = createTagFilters(site_options)

      if not vuln_filter_cats.nil? and not vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      if not vuln_filer_tags.nil? and not vuln_filer_tags.empty?
        vuln_filer_tags.map {|tag| report_config.add_filter('tag', tag.id) }
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end
    
    # Gets the old vulns from base scan reported_scan_id and the newest / latest scan from a site.
    #
    # * *Args*    :
    #   - +site_options+ -  A Hash with site(s), reported_scan_id and severity level.
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def old_vulns_sites(site_options = {})
      report_config =  @report_helper.generate_sql_report_config()
      site = site_options[:site_id]
      reported_scan_id = site_options[:scan_id]
      fail 'Site cannot be null or empty' if site.nil? || reported_scan_id.nil?
      severity = site_options[:severity].nil? ? 0 : site_options[:severity]
      report_config.add_filter('version', '1.2.0')
      report_config.add_filter('query', Queries.old_vulns_since_scan(site_options))
      report_config.add_filter('site', site)
      report_config.add_filter('vuln-severity', severity)

      vuln_filter_cats = createVulnerabilityFilter(site_options)
      vuln_filer_tags = createTagFilters(site_options)

      if not vuln_filter_cats.nil? and not vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      if not vuln_filer_tags.nil? and not vuln_filer_tags.empty?
        vuln_filer_tags.map {|tag| report_config.add_filter('tag', tag.id) }
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end

    # Gets information on possible tickets to close based on only having old vulns/IPs and no new/same ones.
    # Based on IP address (for 'I' mode) or vuln ID ('V' mode).
    #
    # * *Args*    :
    #   - +site_options+ -  A Hash with site(s), reported_scan_id and severity level.
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |comparison|
    #
    def tickets_to_close(site_options = {})
      report_config =  @report_helper.generate_sql_report_config()
      site = site_options[:site_id]
      reported_scan_id = site_options[:scan_id]
      fail 'Site cannot be null or empty' if site.nil? || reported_scan_id.nil?
      severity = site_options[:severity].nil? ? 0 : site_options[:severity]
      report_config.add_filter('version', '1.2.0')
      if site_options[:ticket_mode] == 'V'
        report_config.add_filter('query', Queries.old_tickets_by_vuln_id(site_options))
      else
      report_config.add_filter('query', Queries.old_tickets_by_ip(site_options))
      end
      report_config.add_filter('site', site)
      report_config.add_filter('vuln-severity', severity)

      vuln_filter_cats = createVulnerabilityFilter(site_options)
      vuln_filer_tags = createTagFilters(site_options)

      if not vuln_filter_cats.nil? and not vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      if not vuln_filer_tags.nil? and not vuln_filer_tags.empty?
        vuln_filer_tags.map {|tag| report_config.add_filter('tag', tag.id) }
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end


    # Gets all vulns from base scan reported_scan_id and the newest / latest scan from a site. This is
    # used for IP-based issue updating. Includes the baseline comparision value ('Old','New', or 'Same').
    #
    # * *Args*    :
    #   - +site_options+ -  A Hash with site(s), reported_scan_id and severity level.
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix| |comparison| 
    #
    def all_vulns_sites(site_options = {})
      report_config =  @report_helper.generate_sql_report_config()
      site = site_options[:site_id]
      reported_scan_id = site_options[:scan_id]
      fail 'Site cannot be null or empty' if site.nil? || reported_scan_id.nil?
      severity = site_options[:severity].nil? ? 0 : site_options[:severity]
      report_config.add_filter('version', '1.2.0')
      if site_options[:ticket_mode] == 'V'
        report_config.add_filter('query', Queries.all_vulns_by_vuln_id_since_scan(site_options))
      else
        report_config.add_filter('query', Queries.all_vulns_since_scan(site_options))
      end
      report_config.add_filter('site', site)
      report_config.add_filter('vuln-severity', severity)

      vuln_filter_cats = createVulnerabilityFilter(site_options)
      vuln_filer_tags = createTagFilters(site_options)

      if not vuln_filter_cats.nil? and not vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      if not vuln_filer_tags.nil? and not vuln_filer_tags.empty?
        vuln_filer_tags.map {|tag| report_config.add_filter('tag', tag.id) }
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end


    # Parses user-configured vulnerability filter categories and returns aforementioned categories in a
    # format used by the Nexpose::AdhocReportConfig class.
    #
    # * *Args*    :
    #   - +site_options+ -  A Hash with site(s), reported_scan_id and severity level.
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

    # Parses user-configured tags and returns aforementioned tags in an array containing
    # strings in the format used by the Nexpose::AdhocReportConfig class.
    #
    # * *Args*    :
    #   - +site_options+ -  A Hash with site(s), reported_scan_id and severity level.
    #
    # * *Returns* :
    #   - Returns Array @definedTags
    #
    def createTagFilters(options = {})
      @defined_tags = nil
      if options.has_key?(:tags)
        if not options[:tags].nil? and not options[:tags].empty?
            ## Split the tags into an array
            tag_strings = options[:tags].strip.split(',')

            ## Grab the tag info for the ones we are looking for (if the exist in Nexpose).
            @defined_tags = @nsc.list_tags.select {|nexposeTag| tag_strings.include?(nexposeTag.name)}
        end
      end
      @defined_tags
    end

  end
end
