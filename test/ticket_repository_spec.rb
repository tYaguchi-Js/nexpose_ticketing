require 'rspec'
require 'nexpose_ticketing/ticket_repository'
require 'nexpose_ticketing/queries'
include NexposeTicketing

describe "Ticketing repository" do

  before(:each) do
    @tr = TicketRepository.new
  end
  it 'read the scan history csv' do
    historical_data = @tr.read_last_scans('sample_historical_scan_data.csv')
    expect(historical_data['1']).to eq '3'
  end

  it 'should return -1 for sites not present' do
    historical_data = @tr.read_last_scans('sample_historical_scan_data.csv')
    expect(historical_data['99']).to eq -1
  end

  it 'should save historical csv data' do
    saved_file = double('File')
    report_config = double('Nexpose::AdhocReportConfig')
    mock_last_scan_data = "site_id,last_scan_id,finished\n1,3,2014-01-14 13:15:54.496"
    csv_mock_data = CSV.parse(mock_last_scan_data, headers: :first_row)
    report_config.should_receive(:add_filter).with('version', '1.1.0')
    report_config.should_receive(:add_filter).with('query', Queries.last_scans)
    report_config.should_receive(:generate).with(nil).and_return(mock_last_scan_data)
    saved_file.should_receive(:open).with("mock_file_name.csv", 'w').and_yield(saved_file)
    saved_file.should_receive(:puts).with(csv_mock_data)
    @tr.save_last_scans("mock_file_name.csv", saved_file, report_config)
  end

  it 'should return last scan information' do
    report_config = double('Nexpose::AdhocReportConfig')
    mock_last_scan_data = "site_id,last_scan_id,finished\n1,3,2014-01-14 13:15:54.496"
    report_config.should_receive(:add_filter).with('version', '1.1.0')
    report_config.should_receive(:add_filter).with('query', Queries.last_scans)
    report_config.should_receive(:generate).with(nil).and_return(mock_last_scan_data)
    last_scan_data = @tr.last_scans(report_config)
    expect(last_scan_data['1']).to eq 3
  end

  it 'should not parse and create non-existent last scan data' do
    report_config = double('Nexpose::AdhocReportConfig')
    mock_last_scan_data = "site_id,last_scan_id,finished\n1,3,2014-01-14 13:15:54.496"
    report_config.should_receive(:add_filter).with('version', '1.1.0')
    report_config.should_receive(:add_filter).with('query', Queries.last_scans)
    report_config.should_receive(:generate).with(nil).and_return(mock_last_scan_data)
    last_scan_data = @tr.last_scans(report_config)
    expect(last_scan_data['99']).to eq -1
  end

  it 'all vulnerabilities should generate a report with all vulnerabilities and no site defined' do
    report_config = double('Nexpose::AdhocReportConfig')
    report_config.should_receive(:add_filter).with('version', '1.1.0')
    report_config.should_receive(:add_filter).with('query', Queries.all_delta_vulns)
    report_config.should_not_receive(:add_filter).with('site', anything)
    report_config.should_receive(:add_filter).with('vuln-severity', anything)
    report_config.should_receive(:generate).with(nil)
    @tr.all_vulns({}, report_config)
  end

  it 'should generate an all vulnerabilities report with all vulnerabilities and a site defined' do
    report_config = double('Nexpose::AdhocReportConfig')
    report_config.should_receive(:add_filter).with('version', '1.1.0')
    report_config.should_receive(:add_filter).with('query', Queries.all_delta_vulns)
    report_config.should_receive(:add_filter).with('site', anything)
    report_config.should_receive(:add_filter).with('vuln-severity', anything)
    report_config.should_receive(:generate).with(nil)
    @tr.all_vulns({:sites => [1]}, report_config)
  end

  it 'should generate an all vulnerabilities report with all sites defined' do
    report_config = double('Nexpose::AdhocReportConfig')
    report_config.should_receive(:add_filter).with('version', '1.1.0')
    report_config.should_receive(:add_filter).with('query', Queries.all_delta_vulns)
    report_config.should_receive(:add_filter).with('site', anything).at_most(:twice)
    report_config.should_receive(:add_filter).with('vuln-severity', anything)
    report_config.should_receive(:generate).with(nil)
    @tr.all_vulns({:sites => [1, 2]}, report_config)
  end

  it 'delta vuns should raise an exception if no reported scan id is defined' do
    report_config = double('Nexpose::AdhocReportConfig')
    expect{@tr.delta_vulns_sites({:site => '1'}, report_config)}.to raise_error
  end

  it 'delta vuns should raise an exception if no site is defined' do
    report_config = double('Nexpose::AdhocReportConfig')
    expect{@tr.delta_vulns_sites({}, report_config)}.to raise_error
  end

  it 'delta vuns should generate a report with a site and a scan id defined' do
    report_config = double('Nexpose::AdhocReportConfig')
    report_config.should_receive(:add_filter).with('version', '1.1.0')
    report_config.should_receive(:add_filter).with('query', Queries.delta_vulns_since_scan(1))
    report_config.should_receive(:add_filter).with('site', '1')
    report_config.should_receive(:add_filter).with('vuln-severity', anything)
    report_config.should_receive(:generate).with(nil)
    @tr.delta_vulns_sites({ :site_id => '1', :scan_id => 1 }, report_config)
  end

end