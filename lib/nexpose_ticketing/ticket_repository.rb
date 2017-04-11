module NexposeTicketing
  # Repository class that creates and returns generated reports.
  class TicketRepository
    require 'csv'
    require 'nexpose'
    require 'nexpose_ticketing/queries'
    require 'nexpose_ticketing/report_helper'
    require 'nexpose_ticketing/nx_logger'
    require 'nexpose_ticketing/version'

    API_VERSION = '1.2.0'
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
      @nsc = Nexpose::Connection.new(nexpose_data[:nxconsole],
                                     nexpose_data[:nxuser],
                                     nexpose_data[:nxpasswd])
      @nsc.login
      @log = NexposeTicketing::NxLogger.instance
      @log.on_connect(nexpose_data[:nxconsole], 3780, @nsc.session_id, '{}')

      #After login, create the report helper
      @report_helper = NexposeReportHelper::ReportOps.new(@nsc, @timeout)
    end

    # Logs a message if logging is enabled.
    def log_message(message)
      @log.log_message(message)
    end

    def log_debug_message(message)
      @log.log_debug_message(message)
    end

    def get_solution_data
      report_config =  @report_helper.generate_sql_report_config()
      report_config.add_filter('version', API_VERSION)
      report_config.add_filter('query', Queries.all_solutions)
      @report_helper.save_generate_cleanup_report_config(report_config)
    end

    def get_asset_list(item, mode)
      self.send("get_#{mode}_asset_list", item)
    end

    def get_site_asset_list(site_id)
      @nsc.assets(site_id)
    end

    def get_tag_asset_list(tag_id)
      Nexpose::Tag.load(@nsc, tag_id).asset_ids
    end

    def get_vuln_instances(asset_id, severity = 0)
      @nsc.list_device_vulns(asset_id).select {|vuln| vuln.severity >= severity}
    end

    def get_asset_ip(asset_id)
      Nexpose::Asset.load(@nsc, asset_id).ip
    end

    def create_solution_hash(options, nexpose_item)
      self.send("create_solution_hash#{@method_suffix}", options, nexpose_item)
    end

    def create_solution_hash_by_ip(options, nexpose_item)
      report = all_new_vulns(options, nexpose_item)

      info = {}
      CSV.foreach(report) do |row|
        asset_id, vulnerability_id, first_discov,
            most_recently_discov, solution_ids = row

        next if asset_id == 'asset_id'
        unless info.key? asset_id.to_s
          info[asset_id.to_s] = {}
        end

        info[asset_id.to_s][vulnerability_id.to_s] = {
            first_discovered: first_discov,
            most_recently: most_recently_discov,
            solution_ids: solution_ids }
      end
      info
    end

    def create_solution_hash_by_vuln_id(options, nexpose_item)
      report = all_new_vulns(options, nexpose_item)

      info = {}
      CSV.foreach(report) do |row|
        vulnerability_id, solution_ids, references = row

        next if vulnerability_id == 'vulnerability_id'
        unless info.key? vulnerability_id.to_i
          info[vulnerability_id.to_i] = {}
        end

        info[vulnerability_id.to_i] = { solution_ids: solution_ids,
                                        refs: references }
      end
      info
    end

    # Method retrieves current state of a site / tag from Nexpose for use in a
    # Ticketing Integration
    #
    # Params:
    # - Options: The options to use to generate information
    # - Nexpose_Item: The ID of the Site / Tag to generate data for
    #
    # Returns: CSV containing vulnerability information
    def generate_initial_scan_data(options, nexpose_item)
      self.send("initial_scan#{@method_suffix}", options, nexpose_item)
    end

    def initial_scan_by_ip(options, nexpose_item)
      log_message "Getting vuln info for #{options[:scan_mode]}: " \
                  "#{nexpose_item}"

      query_options = options.dup
      query_options[:report_type] = 'initial' if options[:tag_run]
      info_hash = create_solution_hash_by_ip(query_options, nexpose_item)

      log_debug_message "Getting assets for #{nexpose_item}"
      assets = get_asset_list(nexpose_item, options[:scan_mode])

      initial_scan_file = Tempfile.new("vulnerable_items_#{nexpose_item}")
      initial_scan_file.binmode

      log_debug_message 'Creating CSV for helper'
      CSV.open(initial_scan_file, 'wb') do |csv|
        csv << ['asset_id', 'vulnerability_id', 'first_discovered',
                'most_recently_discovered', 'ip_address', 'riskscore',
                'vuln_nexpose_id', 'cvss_score', 'solution_ids']

        assets.each do |asset|
          if options[:tag_run]
            asset_id = asset.to_s
            asset_deets = Nexpose::Asset.load(@nsc, asset)
            address = asset_deets.ip
            risk_score = asset_deets.assessment.risk_score
          else
            asset_id = asset.id.to_s
            address = asset.address
            risk_score = asset.risk_score
          end

          next if risk_score < (options[:riskScore] || 0)

          log_debug_message "Getting vulns for asset #{address}"
          vulns = get_vuln_instances(asset_id, options[:severity])
          vulns.each do |vuln|
            info = info_hash[asset_id][vuln.console_id.to_s]
            csv << [asset_id, vuln.console_id, info[:first_discovered],
                    info[:most_recently], address, risk_score,
                    vuln.id, vuln.cvss_score, info[:solution_ids]]
          end
        end
      end
      initial_scan_file.flush

      initial_scan_file
    end

    def initial_scan_by_vuln_id(options, nexpose_item)
      log_message "Getting vuln info for #{options[:scan_mode]}: " \
                  "#{nexpose_item}"
      soln_ref_hash = create_solution_hash_by_vuln_id(options, nexpose_item)

      log_debug_message "Getting assets for #{nexpose_item}"
      assets = get_asset_list(nexpose_item, options[:scan_mode])
      current_vuln_instances = {}
      assets.each do |asset|
        next if asset.risk_score < (options[:riskScore] || 0)

        vulns = get_vuln_instances(asset.id.to_s, options[:severity])

        vulns.each do |vuln|
          unless current_vuln_instances.key? vuln.console_id
            current_vuln_instances[vuln.console_id] = { vuln: vuln.id,
                                                        assets: [] }
          end

          current_vuln_instances[vuln.console_id][:assets] << asset
        end
      end

      initial_scan_file = Tempfile.new("vulnerable_items_#{nexpose_item}")
      initial_scan_file.binmode
      log_debug_message 'Creating CSV for helper'

      CSV.open(initial_scan_file, 'wb') do |csv|
        csv << ['vulnerability_id', 'vuln_nexpose_id', 'title', 'cvss_score',
                'assets', 'description', 'solution_ids', 'references']
        current_vuln_instances.each do |vuln_id, data|
          vuln_def = Nexpose::VulnerabilityDefinition.load(@nsc, data[:vuln])
          assets = []
          data[:assets].each do |asset|
            assets << "#{asset.id}|#{asset.address}|#{asset.risk_score}"
          end

          csv << [vuln_id, data[:vuln], vuln_def.title, vuln_def.cvss_score,
                  assets.join('~'), vuln_def.description,
                  soln_ref_hash[vuln_id][:solution_ids],
                  soln_ref_hash[vuln_id][:refs]]
        end
      end
      initial_scan_file.flush

      initial_scan_file
    end

    # Method retrieves current state of a site from Nexpose, before creating a
    # diff against the state the last time the integration was run.
    #
    # Params:
    # - Options: The options to use to generate information
    #
    # Returns: The current state of vulnerabilities for assets in a site.
    #
    def generate_delta_scan_data(options)
      self.send("delta_scan#{@method_suffix}", options)
    end

    def delta_scan_by_ip(options)
      current_vuln_instances = {}
      current_vuln_ids  = {}
      ignored_assets = []

      assets = if options[:tag_run]
                 [Nexpose::Asset.load(@nsc, options[:nexpose_item])]
               else
                 get_site_asset_list(options[:nexpose_item])
               end

      assets.each do |asset|
        risk_score = if options[:tag_run]
                       asset.assessment.risk_score
                     else
                       asset.risk_score
                     end
        if risk_score < (options[:riskScore] || 0)
          ignored_assets << asset.id
          next
        end

        vulns = get_vuln_instances(asset.id, options[:severity])
        current_vuln_instances[asset.id.to_s] = { asset: asset, vulns: vulns }
        current_vuln_ids[asset.id.to_s] = vulns.map { |v| v.console_id }
      end

      state = {}
      previous_state_file = get_previous_state(options,
                                               'last_scan_state_by_ip')

      CSV.foreach(previous_state_file, headers: true) do |row|
        asset_id = row['asset_id'].to_s
        vuln_id = row['vulnerability_id'].to_i

        next if ignored_assets.include? asset_id

        if current_vuln_ids.key? asset_id
          unless state.key? asset_id.to_s
            state[asset_id] =
                { asset: current_vuln_instances[asset_id][:asset], new: [],
                  same: [], old: [] }
          end

          success = current_vuln_ids[asset_id].delete(vuln_id)
          if success.nil?
            state[asset_id][:old] << vuln_id
          else
            vulns = current_vuln_instances[asset_id][:vulns]
            state[asset_id][:same] << vulns.find { |v| v.console_id == vuln_id }
          end
        else
          unless state.key? asset_id
            state[asset_id] = { old_ticket: '', new: [], same: [], old: [] }
          end

          state[asset_id][:old] << vuln_id
        end
      end

      current_vuln_ids.each_key do |asset_id|
        asset_id = asset_id.to_s
        unless state.key? asset_id
          state[asset_id] =
              { asset: current_vuln_instances[asset_id][:asset], new: [],
                same: [], old: [] }
        end

        current_vuln_ids[asset_id].each do |vuln_id|
          vulns = current_vuln_instances[asset_id][:vulns]
          state[asset_id][:new] << vulns.find { |v| v.console_id == vuln_id }
        end
      end

      state.each_key do |asset_id|
        if state[asset_id][:new].size == 0 && state[asset_id][:same].size == 0
          state[asset_id][:old_ticket] = ''
        end
      end

      state
    end

    def delta_scan_by_vuln_id(options)
      current_vuln_instances = {}
      current_vuln_ids = {}
      ignored_assets = []
      assets = get_site_asset_list(options[:nexpose_item])

      assets.each do |asset|
        if asset.risk_score < (options[:riskScore] || 0)
          ignored_assets << asset.id
          next
        end
        vulns = get_vuln_instances(asset.id.to_s, options[:severity])

        vulns.each do |vuln|
          console_id = vuln.console_id
          unless current_vuln_instances.key? console_id
            current_vuln_instances[console_id] = { vuln: vuln.id,
                                                   assets: {} }
            current_vuln_ids[console_id] = []
          end

          current_vuln_instances[console_id][:assets][asset.id] = asset
          current_vuln_ids[console_id] << asset.id
        end
      end

      state = {}
      previous_state_file = get_previous_state(options,
                                               'last_scan_state_by_vuln_id')

      CSV.foreach(previous_state_file, headers: true) do |row|
        vuln_id = row['vulnerability_id'].to_i
        asset_ids = row['asset_ids'][1..-2].split(',').map(&:to_i)

        if current_vuln_ids.key? vuln_id
          unless state.key? vuln_id
            state[vuln_id] = { vuln: current_vuln_instances[vuln_id][:vuln],
                               new: [], same: [], old: [] }
          end

          asset_ids.each do |asset_id|            
            next if ignored_assets.include? asset_id

            success = current_vuln_ids[vuln_id].delete(asset_id)

            if success.nil?
              asset_info = { id: asset_id, ip: get_asset_ip(asset_id) }
              state[vuln_id][:old] << asset_info
            else
              asset = current_vuln_instances[vuln_id][:assets][asset_id]
              state[vuln_id][:same] << asset
            end
          end
        else
          unless state.key? vuln_id
            state[vuln_id] = { vuln: vuln_id, old_ticket: 1, new: [],
                               same: [], old: [] }
          end

          state[vuln_id][:old] << asset_ids
        end
      end

      current_vuln_ids.each_key do |vuln_id|
        unless state.key? vuln_id
          state[vuln_id] =
              { vuln: current_vuln_instances[vuln_id][:vuln], new: [],
                same: [], old: [] }
        end

        current_vuln_ids[vuln_id].each do |asset_id|
          asset = current_vuln_instances[vuln_id][:assets][asset_id]
          state[vuln_id][:new] << asset
        end
      end

      state.each_key do |vuln_id|
        if state[vuln_id][:new].size == 0 && state[vuln_id][:same].size == 0
          state[vuln_id][:old_ticket] = 1
        end
      end

      state
    end

    # Method converts retrieved information from Nexpose, sorted by the current
    # state, into a CSV to be parsed into tickets for sending to a third party
    # service
    #
    # Params:
    # - options: The options to use to generate information
    # - close_tickets: Whether the user has ticket closures enabled
    #
    # Returns: A CSV containing all necessary information to create tickets
    #
    def generate_delta_csv(options, close_tickets)
      self.send("generate_delta_csv#{@method_suffix}", options, close_tickets)
    end

    def generate_delta_csv_by_ip(options, close_tickets)
      nexpose_item = options[:nexpose_item]

      state = generate_delta_scan_data(options)
      info_hash = create_solution_hash(options, nexpose_item)

      delta_scan_file = Tempfile.new("delta_vulnerable_items_#{nexpose_item}")
      delta_scan_file.binmode

      CSV.open(delta_scan_file, 'wb') do |csv|
        csv << ['asset_id', 'vulnerability_id', 'first_discovered',
                'most_recently_discovered', 'ip_address', 'riskscore',
                'vuln_nexpose_id', 'cvss_score', 'solution_ids', 'comparison']

        state.each do |asset_id, vulns|
          asset = vulns[:asset]
          asset_id = asset.id.to_s

          if options[:tag_run]
            address = asset.ip
            risk_score = asset.assessment.risk_score
          else
            address = asset.address
            risk_score = asset.risk_score
          end

          if vulns.key? :new
            vulns[:new].each do |vuln|
              info = info_hash[asset_id][vuln.console_id.to_s]
              csv << [asset_id, vuln.console_id, info[:first_discovered],
                      info[:most_recently], address, risk_score,
                      vuln.id, vuln.cvss_score, info[:solution_ids], 'New']
            end
          end

          if vulns.key? :same
            vulns[:same].each do |vuln|
              info = info_hash[asset_id][vuln.console_id.to_s]
              csv << [asset_id, vuln.console_id, info[:first_discovered],
                      info[:most_recently], address, risk_score,
                      vuln.id, vuln.cvss_score, info[:solution_ids], 'Same']
            end
          end
        end
      end

      delta_scan_file.flush
      unless close_tickets
        return { new_csv: delta_scan_file }
      end

      old_vulns_file = Tempfile.new("delta_vuln_old_items_#{nexpose_item}")
      old_vulns_file.binmode

      old_vulns_mode = options[:old_vulns_mode]
      CSV.open(old_vulns_file, 'wb') do |csv|
        csv << %w(asset_id vulnerability_id ip_address)

        if old_vulns_mode == 'old'
          key = old_vulns_mode.intern
          old_vulns = state.select { |asset_id, vulns| vulns[key].size > 0 }
          old_vulns.each do |asset_id, vulns|
            asset = old_vulns[asset_id][:asset]
            vulns[:old].each do |vuln|
              csv << [asset_id, vuln, asset.address]
            end
          end
        else
          key = old_vulns_mode.intern
          old_vulns = state.select{ |asset_id, vulns| vulns.key? key }
          old_vulns.each do |asset_id, vulns|
            ip = if vulns.key? :asset
                   vulns[:asset].address
                 else
                   get_asset_ip(asset_id)
                 end
            csv << [asset_id, '', ip]
          end
        end
      end

      old_vulns_file.flush
      { new_csv: delta_scan_file, old_csv: old_vulns_file }
    end

    def generate_delta_csv_by_vuln_id(options, close_tickets)
      nexpose_item = options[:nexpose_item]

      state = generate_delta_scan_data(options)
      info = create_solution_hash(options, nexpose_item)

      delta_scan_file = Tempfile.new("delta_vulnerable_items_#{nexpose_item}")
      delta_scan_file.binmode

      old_tickets = []
      CSV.open(delta_scan_file, 'wb') do |csv|
        csv << ['vulnerability_id', 'vuln_nexpose_id', 'title', 'cvss_score',
                'assets', 'description', 'solution_ids', 'references',
                'comparison']

        state.each do |vuln_id, data|
          if data.has_key? :old_ticket
            old_tickets << vuln_id
            next
          end

          vuln = data[:vuln]
          vuln_def = Nexpose::VulnerabilityDefinition.load(@nsc, vuln)

          if data[:new].count > 0
            assets = []
            data[:new].each do |asset|
              assets << "#{asset.id}|#{asset.address}|#{asset.risk_score}"
            end
            csv << [vuln_id, vuln, vuln_def.title, vuln_def.cvss_score,
                    assets.join('~'), vuln_def.description,
                    info[vuln_id][:solution_ids], info[vuln_id][:refs], 'New']

            if data[:same].count > 0
              assets = []
              data[:same].each do |asset|
                assets << "#{asset.id}|#{asset.address}|#{asset.risk_score}"
              end

              csv << [vuln_id, vuln, vuln_def.title, vuln_def.cvss_score,
                      assets.join('~'), '', '', '', 'Same']
            end
          elsif data[:same].count > 0
            assets = []
            data[:same].each do |asset|
              assets << "#{asset.id}|#{asset.address}|#{asset.risk_score}"
            end
            csv << [vuln_id, vuln, vuln_def.title, vuln_def.cvss_score,
                    assets.join('~'), vuln_def.description,
                    info[vuln_id][:solution_ids], info[vuln_id][:refs], 'Same']
          end

          if data[:old].count > 0
            assets = []
            data[:old].each do |asset|
              assets << "#{asset[:id]}|#{asset[:ip]}|"
            end

            csv << [vuln_id, vuln, vuln_def.title, vuln_def.cvss_score,
                    assets.join('~'), '', '', '', 'Old']
          end
        end
      end
      delta_scan_file.flush

      unless close_tickets
        return { new_csv: delta_scan_file }
      end

      old_vulns_file = Tempfile.new("delta_vuln_old_items_#{nexpose_item}")
      old_vulns_file.binmode

      CSV.open(old_vulns_file, 'wb') do |csv|
        csv << %w(vulnerability_id)
        old_tickets.each { |id| csv << [id] }
      end

      old_vulns_file.flush
      { new_csv: delta_scan_file, old_csv: old_vulns_file }
    end

    # Returns the previous state of a site
    def get_previous_state(options, query_name)
      report_config =  @report_helper.generate_sql_report_config()
      report_config.add_filter('version', API_VERSION)
      report_config.add_filter('query', Queries.send(query_name, options))
      if options[:tag_run]
        report_config.add_filter('device', options[:nexpose_item].to_s)
      else
        report_config.add_filter('site', options[:nexpose_item])
      end

      report_config.add_filter('vuln-severity', options[:severity] || 0)

      @report_helper.save_generate_cleanup_report_config(report_config)
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
    def load_last_scans(options = {})
      @nsc.login

      if options[:tag_run]
        # Need a scan ID for every asset associated with that tag
        tags = Array(options[:tags]).map!(&:to_s)
        scan_details = CSV.generate do |csv|
          csv << %w(tag_id asset_id last_scan_id scan_finished)

          tags.each do |t|
            assets = Nexpose::Tag.load(@nsc, t).asset_ids
            assets.each do |a|
              latest = @nsc.asset_scan_history(a).max_by { |s| s.scan_id }
              csv << [t, a, latest.scan_id, latest.end_time]
            end
          end
        end
      else
        sites = Array(options[:sites]).map!(&:to_s)
        scan_details = CSV.generate do |csv|
          csv << %w(site_id last_scan_id finished)
          sites.each do |s|
            scan = @nsc.last_scan(s)
            csv << [s, scan.scan_id, scan.end_time]
          end
        end
      end

      csv_output = CSV.parse(scan_details.chomp,  headers: :first_row)

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
        trimmed_csv << scan_details.lines.first
        csv_output.each do |row|
          trimmed_csv << row
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

    def generate_tag_asset_list(options = {})
      tags = Array(options[:tags]).map!(&:to_s)

      tags.each do |t|
        trimmed_csv = ['asset_id, last_scan_id']

        assets = Nexpose::Tag.load(@nsc, t).asset_ids
        assets.each do |a|
          scan = @nsc.asset_scan_history(a).max_by { |s| s.scan_id }
          trimmed_csv << "#{a},#{scan.scan_id}"
        end
        save_to_file(options[:csv_file], trimmed_csv)
      end
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
      items = if nexpose_items
                Array(nexpose_items)
              elsif options[:nexpose_item]
                nil
              else
                options["#{options[:scan_mode]}s".intern]
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

      id_type = if options[:report_type].to_s == 'initial'
                  'tag'
                elsif options[:tag_run]
                  'device'
                else
                  'site'
                end

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

      log_message %Q{Creating query request "#{full_method_name}".}
      request_query(full_method_name, args[0], args[1])
    end

  end
end
