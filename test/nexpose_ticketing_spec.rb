require 'rspec'
require 'nexpose_ticketing/ticket_service'

describe 'Ticketing service' do

  before(:each) do
    @ts = NexposeTicketing::TicketService.new
    @ts.options = { logging_enabled: false }
    @tr = double('TicketRepository')
    @helper = double('helper')
  end

  it 'should return historical data if it exists' do
    options = { file_name: 'sample_historical_scan_data.csv' }
    call_file_name = File.join(File.dirname(__FILE__), 'sample_historical_scan_data.csv')
    sample_historical_data = 'site_id,last_scan_id,finished\n1,3,2014-01-14 13:15:54.496'
    @tr.should_receive(:read_last_scans).with(call_file_name).and_return(sample_historical_data)
    @tr.should_not_receive(:save_last_scans).with(call_file_name)
    @ts.options = options
    returned_historical_data = @ts.prepare_historical_data(@tr, options, call_file_name)
    expect(returned_historical_data).to eq sample_historical_data
  end

  it 'should generate and save historical data if it does not exists already' do
    options = { file_name: 'no_file.csv' }
    call_file_name = File.join(File.dirname(__FILE__), 'no_file.csv')
    sample_historical_data = "site_id,last_scan_id,finished\n1,3,2014-01-14 13:15:54.496"
    @tr.should_receive(:save_last_scans).with(call_file_name)
    @tr.should_receive(:read_last_scans).with(call_file_name).and_return(sample_historical_data)
    @ts.options = options
    returned_historical_data = @ts.prepare_historical_data(@tr, options, call_file_name)
    expect(returned_historical_data).to eq sample_historical_data
    expect(@ts.first_time).to eq true
  end

  it 'should generate a full sites report ticket' do
    local_report = IO.read('data_report.csv')
    call_file_name = File.join(File.dirname(__FILE__), 'sample_historical_data.csv')
    options = { severity: '5', file_name: call_file_name, sites: [] }
    @tr.should_receive(:all_vulns).with(severity: options[:severity]).and_return(local_report)
    @helper.should_receive(:prepare_tickets).with(local_report).and_return('Sample ticket')
    @helper.should_receive(:create_ticket).with('Sample ticket')
    @tr.should_receive(:save_last_scans).with(options[:file_name])
    @ts.all_site_report(@tr, options, @helper, call_file_name)
  end

  it 'should detect a new scan with no new vulnerability data and no new sites' do
    no_file = File.join(File.dirname(__FILE__), 'no_file.csv')
    options = { file_name: no_file }
    @ts.nexpose_site_histories = { '1' => 3 }
    file_site_histories = { '1' => '3' }
    @tr.should_receive(:save_last_scans).with(options[:file_name])
    processing = @ts.delta_site_report(@tr, options, @helper, file_site_histories, no_file)
    expect(processing).to eq true
  end

  it 'should detect a new scan with new vulnerabilities' do
    no_file = File.join(File.dirname(__FILE__), 'no_file.csv')
    options = { file_name: no_file }
    @ts.nexpose_site_histories = { '1' => 4 }
    file_site_histories = { '1' => '3' }
    @ts.should_receive(:delta_site_new_scan).and_return(false)
    @tr.should_receive(:save_last_scans).with(options[:file_name])
    processing = @ts.delta_site_report(@tr, options, @helper, file_site_histories, no_file)
    expect(processing).to eq false
  end

  it 'should detect a new site in nexpose' do
    no_file = File.join(File.dirname(__FILE__), 'no_file.csv')
    options = { file_name: no_file }
    @ts.nexpose_site_histories = { '1' => 4 }
    @ts.should_receive(:full_new_site_report).and_return(false)
    @tr.should_receive(:save_last_scans).with(options[:file_name])
    processing = @ts.delta_site_report(@tr, options, @helper, { siteid: '-1' }, no_file)
    expect(processing).to eq false
  end

  it 'should generate a new site report' do
    options = { severity: '5', file_name: 'sample_historical_data.csv', sites: %w('1' '2') }
    local_report = IO.read('data_report.csv')
    @tr.should_receive(:all_vulns).with(sites: ['1'], severity: options[:severity]).and_return(local_report)
    @helper.should_receive(:prepare_tickets).with(local_report).and_return('Sample ticket')
    @helper.should_receive(:create_ticket).with('Sample ticket')
    @ts.full_new_site_report('1', @tr, options, @helper)
  end

  it 'should not prepare tickets with an empty new scan report' do
    empty_report = IO.read('empty_report.csv')
    file_site_histories = { '1' => '9' }
    options = { severity: '8', file_name: 'sample_historical_data.csv', site_id: '1' }
    @tr.should_receive(:delta_vulns_sites).with(scan_id: '9', site_id: '1', severity: '8').and_return(empty_report)
    @helper.should_not_receive(:prepare_tickets).with(empty_report)
    @helper.should_not_receive(:create_ticket).with(anything)
    @ts.delta_site_new_scan(@tr, '1', options, @helper, file_site_histories)
  end

  it 'should prepare tickets when a report with data is generated' do
    data_report = IO.read('data_report.csv')
    file_site_histories = { '1' => '9' }
    options = { severity: '8', file_name: 'sample_historical_data.csv', site_id: '1' }
    @tr.should_receive(:delta_vulns_sites).with(scan_id: '9', site_id: '1', severity: '8').and_return(data_report)
    @helper.should_receive(:prepare_tickets).with(data_report).and_return('Sample ticket')
    @helper.should_receive(:create_ticket).with('Sample ticket')
    @ts.delta_site_new_scan(@tr, '1', options, @helper, file_site_histories)
  end
end
