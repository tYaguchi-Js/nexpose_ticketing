module NexposeTicketing
  # Repository class that creates and returns generated reports.
  class TicketRepository
    require 'csv'
    require 'nexpose'
    require 'nexpose_ticketing/queries'

    def nexpose_login(nexpose_data)
      @nsc = Nexpose::Connection.new(nexpose_data[:nxconsole], nexpose_data[:nxuser], nexpose_data[:nxpasswd])
      @nsc.login
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
    def save_last_scans(csv_file_name, saved_file = nil, report_config = Nexpose::AdhocReportConfig.new(nil, 'sql'))
      report_config.add_filter('version', '1.1.0')
      report_config.add_filter('query', Queries.last_scans)
      report_output = report_config.generate(@nsc)
      csv_output = CSV.parse(report_output.chomp,  headers: :first_row)
      saved_file.open(csv_file_name, 'w') { |file| file.puts(csv_output) } unless saved_file.nil?
      if saved_file.nil?
        File.open(csv_file_name, 'w') { |file| file.puts(csv_output) }
      end
    end

    # Gets the last scan information from nexpose.
    #
    # * *Returns* :
    #   - A hash with site_ids => last_scan_id
    #
    def last_scans(report_config = Nexpose::AdhocReportConfig.new(nil, 'sql'))
      report_config.add_filter('version', '1.1.0')
      report_config.add_filter('query', Queries.last_scans)
      report_output = report_config.generate(@nsc).chomp
      nexpose_sites = Hash.new(-1)
      CSV.parse(report_output, headers: :first_row)  do |row|
        nexpose_sites[row['site_id']] = row['last_scan_id'].to_i
      end
      nexpose_sites
    end

    # Gets all the vulnerabilities for a new site or fresh install.
    #
    # * *Args*    :
    #   - +site_options+ -  A Hash with site(s) and severity level.
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def all_vulns(site_options = {}, report_config = Nexpose::AdhocReportConfig.new(nil, 'sql'))
      sites = Array(site_options[:sites])
      severity = site_options[:severity].nil? ? 0 : site_options[:severity]
      report_config.add_filter('version', '1.1.0')
      report_config.add_filter('query', Queries.all_delta_vulns)
      unless sites.empty?
        sites.each do |site_id|
          report_config.add_filter('site', site_id)
        end
      end
      report_config.add_filter('vuln-severity', severity)
      report_config.generate(@nsc)
    end

    # Gets the delta vulns from base scan reported_scan_id and the newest / latest scan from a site.
    #
    # * *Args*    :
    #   - +site_options+ -  A Hash with site(s), reported_scan_id and severity level.
    #
    # * *Returns* :
    #   - Returns CSV |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def delta_vulns_sites(site_options = {}, report_config = Nexpose::AdhocReportConfig.new(nil, 'sql'))
      site = site_options[:site_id]
      reported_scan_id = site_options[:scan_id]
      fail 'Site cannot be null or empty' if site.nil? || reported_scan_id.nil?
      severity = site_options[:severity].nil? ? 0 : site_options[:severity]
      report_config.add_filter('version', '1.1.0')
      report_config.add_filter('query', Queries.delta_vulns_since_scan(reported_scan_id))
      report_config.add_filter('site', site)
      report_config.add_filter('vuln-severity', severity)
      report_config.generate(@nsc)
    end
  end
end
