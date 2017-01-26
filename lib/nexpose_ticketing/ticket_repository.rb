module NexposeTicketing
  # Repository class that creates and returns generated reports.
  class TicketRepository
    require 'csv'
    require 'nexpose'
    require 'nexpose_ticketing/queries'
    require 'nexpose_ticketing/report_helper'
    require 'nexpose_ticketing/nx_logger'
    require 'nexpose_ticketing/version'

    @timeout = 10800

    def initialize(options = nil)
      @timeout = options[:timeout]

      # Gets the suffix of the query method signatures based on the mode
      @method_suffix = options[:query_suffix]

      define_query_methods
    end

    def define_query_methods
      methods = Queries.methods.grep Regexp.new (@method_suffix+'$')
      
      methods.each do |m|
        define_singleton_method m do |options, override=nil|
          request_query(m, options, override)
        end
      end
    end

    def nexpose_login(nexpose_data) 
      @nsc = Nexpose::Connection.new(nexpose_data[:nxconsole], nexpose_data[:nxuser], nexpose_data[:nxpasswd])
      @nsc.login
      @log = NexposeTicketing::NxLogger.instance
      @log.on_connect(nexpose_data[:nxconsole], 3780, @nsc.session_id, "{}")

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
      sites = Array(options[:sites]).map!(&:to_s)
      tags = Array(options[:tags]).map!(&:to_s)

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
        trimmed_csv << 'tag_id,last_scan_fingerprint'
        current_tag_id = nil
        tag_finger_print = ''
        csv_output.each  do |row|
          if (tags.include? row[0].to_s) && (row[0].to_i != current_tag_id)
            if(current_tag_id.nil?)
              #Initial run
              current_tag_id = row[0].to_i
            else
              #New tag ID, finish off the old fingerprint and start on the new one
              trimmed_csv << CSV::Row.new('tag_id,last_scan_fingerprint'.split(','), "#{current_tag_id},#{Digest::MD5::hexdigest(tag_finger_print)}".split(','))
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
          trimmed_csv << CSV::Row.new('tag_id,last_scan_fingerprint'.split(','), "#{current_tag_id},#{Digest::MD5::hexdigest(tag_finger_print)}".split(','))
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
      if options[:vulnerabilityCategories].nil? || options[:vulnerabilityCategories].empty?
        return nil
      end
      
      filter = options[:vulnerabilityCategories].strip.split(',')
      filter.map { |category| "include:#{category}" }.join(',')
    end

    def read_tag_asset_list(csv_file_name)
      file_identifier_histories = Hash.new(-1)
      CSV.foreach(csv_file_name, headers: true) do |row|
        file_identifier_histories[row[0]] = row[1]
      end
      file_identifier_histories
    end

    def generate_tag_asset_list(options = {}, report_config = Nexpose::AdhocReportConfig.new(nil, 'sql'))
      report_config.add_filter('version', '1.2.0')
      tags = Array(options[:tags])
      report_config.add_filter('query', Queries.last_tag_scans)
      tags.each { |tag| report_config.add_filter('tag', tag) }

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

            # TODO: test this change
            trimmed_csv << 'asset_id, last_scan_id'
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
      unless saved_file.nil?
        saved_file.open(csv_file_name, 'w') { |file| file.puts(trimmed_csv) } 
        return
      end

      dir = File.dirname(csv_file_name)
      FileUtils.mkdir_p(dir) unless File.directory?(dir)
      File.open(csv_file_name, 'w') { |file| file.puts(trimmed_csv) }
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

    def request_query(query_name, options = {}, nexpose_items = nil)
      items = 
        if nexpose_items
          Array(nexpose_items)
        else
          options[:nexpose_item] ? nil : options["#{options[:scan_mode]}s".intern]
        end 

      report_config = generate_config(query_name, options, items)
    end

    def generate_config(query_name, options, nexpose_items)
      report_config =  @report_helper.generate_sql_report_config()
      nexpose_item = options[:nexpose_item]
      reported_scan_id = options[:scan_id]

      # If it's a non-initial run, we need the last scan ID
      unless options[:initial_run]
        fail 'Nexpose item cannot be null or empty' if nexpose_item.nil? || reported_scan_id.nil?
      end

      report_config.add_filter('version', '1.2.0')
      report_config.add_filter('query', Queries.send(query_name, options))

      id_type = options[:tag_run] ? 'tag' : 'site'

      if nexpose_items != nil && !nexpose_items.empty?
        nexpose_items.each { |id| report_config.add_filter(id_type, id) }
      else
        item = options[:tag_run] ? options[:tag] : nexpose_item
        report_config.add_filter(id_type, item)
      end 

      report_config.add_filter('vuln-severity', options[:severity] || 0)

      vuln_filter_cats = createVulnerabilityFilter(options)

      unless vuln_filter_cats.nil? || vuln_filter_cats.empty?
        report_config.add_filter('vuln-categories', vuln_filter_cats)
      end

      @report_helper.save_generate_cleanup_report_config(report_config)
    end

    def method_missing(name, *args, &block)
      full_method_name = "#{name}#{@method_suffix}"
    
      unless Queries.respond_to? full_method_name
        fail %Q{Query request "#{full_method_name}" not understood}
      end

      @log.log_message %Q{Creating query request "#{full_method_name}".}
      request_query(full_method_name, args[0], args[1])
    end

  end
end
