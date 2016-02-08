require 'nexpose'
require 'securerandom'
include Nexpose

module NexposeReportHelper
  class ReportOps

    def initialize(nsc, timeout)
      @timeout = timeout
      @nsc = nsc
    end

    def generate_sql_report_config
      random_name = "Nexpose-ticketing-Temp-#{SecureRandom.uuid}"
      Nexpose::ReportConfig.new(random_name, nil, 'sql')
    end

    def save_generate_cleanup_report_config(report_config)
      report_id = report_config.save(@nsc, false)
      @nsc.generate_report(report_id, true)
      wait_for_report(report_id)
      report_details = @nsc.last_report(report_id)
      file = Tempfile.new("#{report_id}")
      file.binmode
      file.write(@nsc.download(report_details.uri))
      file.flush

      #Got the report, cleanup server-side
      @nsc.delete_report_config(report_id)
      file
    end

    # Wait for report generation to complete.
    #
    # @param [Fixnum] id Report configuration ID of the report waiting to generate.
    #
    def wait_for_report(id)
      wait_until(:fail_on_exceptions => TRUE, :on_timeout => "Report generation timed out. Status: #{r = @nsc.last_report(id); r ? r.status : 'unknown'}") {
        if %w(Failed Aborted Unknown).include?(@nsc.last_report(id).status)
          raise "Report failed to generate! Status <#{@nsc.last_report(id).status}>"
        end
        @nsc.last_report(id).status == 'Generated'
      }
    end

    # Wait for a given block to evaluate to true.
    #
    # The following flags are accepted as arguments:
    #   :timeout Number of seconds to wait before timing out. Defaults to 90.
    #   :polling_interval Number of seconds to wait between checking block again.
    #      Defaults to 5.
    #   :fail_on_exceptions Whether to fail fast. Defaults to off.
    #   :on_timeout Message to raise with the exception when a timeout occurs.
    #
    # Example usage:
    #   wait_until { site.id > 0 }
    #   wait_until(:timeout => 30, :polling_interval => 0.5) { 1 == 2 }
    #   wait_until(:on_timeout => 'Unable to confirm scan integration.') { console.sites.find { |site| site[:site_id] == site_id.to_i }[:risk_score] > 0.0 }
    #
    def wait_until(options = {})
      polling_interval = 90
      time_limit = Time.now + @timeout
      loop do
        begin
          val = yield
          return val if val
        rescue Exception => error
          raise error if options[:fail_on_exceptions]
        end
        if Time.now >= time_limit
          raise options[:on_timeout] if options[:on_timeout]
          error ||= 'Timed out waiting for condition.'
          raise error
        end
        sleep polling_interval
      end
    end
    end
end