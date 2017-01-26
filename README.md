# Nexpose Ticketing Engine.

This is the official gem package for the Ruby Nexpose Ticketing engine.

To share your scripts, or to discuss different approaches, please visit the Rapid7 forums for Nexpose: https://community.rapid7.com/community/nexpose

For assistance with using the gem please email the Rapid7 integrations support team at support@rapid7.com.

## About

The Nexpose Ticketing integration allows customers to create incident tickets based upon vulnerabilities found across their systems. The integration runs a report for a chosen site or tag group in Nexpose and then creates tickets based on the report, either for each machine or vulnerability, as specified by the ticketing mode selected. On subsequent scans, new tickets are created, existing tickets are updated (and potentially closed if resolved) based on any differences since the previous scan was performed.

The integration has three ticket generation modes:
* Default mode: This mode will create one ticket per instance of a vulnerability i.e. a vulnerability present on three machines will have three tickets. This mode makes for smaller, more actionable incidents but has the potential to generate a large number of tickets. This mode can only create and close tickets. It does not update any information in existing tickets.
* IP mode: This mode creates a single ticket containing all vulnerabilities for each asset. This reduces the total number of incidents but can greatly increase the size of work notes. On subsequent scans the ticket is updated to include new vulnerabilities and will mark fixed issues as 'old'.
* Vulnerability mode: This mode will create a ticket for each vulnerability, listing every scanned asset affected by this vulnerability. This reduces the total number of incidents but can greatly increase the size of work notes. On subsequent scans the ticket is updated to include any new information about the vulnerability and new assets with this vulnerability. Vulnerability mode is not compatable with tag runs.

`Ruby Version: >= 2.1.5`

`Supported Ticketing systems: JIRA; Remedy ITSM; ServiceNow; ServiceDesk`

For more information, as well as service specific information, please refer to the integration documentation which can be requested from the Rapid7 support team.

## Installation

Ticketing service integrations with Nexpose require the nexpose_ticketing Ruby gem that facilitates communication between Nexpose and the various ticketing services. Before installing the gem, ensure a Ruby interpreter is installed on the system running the gem, as well as RubyGems.

To install the gem, run the command: 
```ruby
$ gem install nexpose_ticketing
```
## Usage

Documentation for setting up each integration can be requested from support@rapid7.com

To use the JIRA implementation please follow these steps:
* Edit the jira.config file under the gem config folder and add the necessary data.
* Edit the ticket_service.config under the gem config folder and add the necessary data.
* Run the nexpose_ticketing file under the bin folder. If installed with gem the command `console> nexpose_ticketing jira` should suffice. Replace 'jira' with your chosen helper for other implementations

Note: Gem is usually installed under
 * Windows: C:\Ruby\<version\>\lib\ruby\gems\version\gems
 * Linux: /var/lib/gems/\<version\>/gems/ or /home/\<user\>/.rvm/gems/\<version\>/gems/

Please refer to your particular Ruby documentation for actual installation folder.

A logger is also implemented by default, and the log can be found under `<install_location>/lib/nexpose_ticketing/logs/`
Please refer to the log file in case of an error.

## Contributions

To develop your own implementation for Ticketing service 'foo':

1. Create a helper class that implements the following methods:
	* Initialize: This is the constructor that will take the implementation options and the service options. It should inherit from the base_helper class.
	* create_ticket(tickets) - This method should implement the transport class for the 'foo' service (https, smtp, SOAP, etc).
	* prepare_create_tickets(vulnerability_list, nexpose_identifier_id) - This method will take the vulnerability_list in CSV format and transform it into 'foo' accepted data (JSON, XML, etc). The implemented helpers group data into a single ticket according to the current ticketing mode: Per IP in IP mode and per vulnerability in Vulnerability mode.

2. For full functionality (updating and closing tickets), also implement the following methods:
	* update_tickets(tickets) - This method should implement the transport class for the 'foo' service (https, smtp, SOAP, etc), to send updated ticket descriptions to the service for specific existing tickets.
	* prepare_update_tickets(vulnerability_list, nexpose_identifier_id) - This method will take the vulnerability_list in CSV format and transform it into 'foo' accepted data (JSON, XML, etc) for updating exisiting tickets.
	* close_tickets(tickets) - This method should implement the transport class for the 'foo' service (https, smtp, SOAP, etc), to send closure messages to the service for a specific exisiting ticket.
	* prepare_close_tickets(vulnerability_list, nexpose_identifier_id) - This method will take the vulnerability_list in CSV format and transform it into 'foo' accepted data (JSON, XML, etc) containing information about the tickets to close.

3. A configuration file will be needed in the config folder for service specific options. This is loaded at the start of operation. Please refer to the existing configuration files, as certain options are common to all services.

Please see jira\_helper.rb under helpers for an helper example, and two\_vulns\_report.csv under the test folder for a sample CSV report. For more information about developing a new helper, including implementing the different ticketing modes, please see the 'Developer Guide for Nexpose Ticketing' document.

We welcome contributions to this package. We ask only that pull requests and patches adhere to our coding standards.

* Favor returning classes over key-value maps. Classes tend to be easier for users to manipulate and use.
* Unless otherwise noted, code should adhere to the [Ruby Style Guide] (https://github.com/bbatsov/ruby-style-guide).
* Use YARDoc comment style to improve the API documentation of the gem.
* Pull requests may not be accepted for user specific use-cases.

##Changelog

###1.3.0
25-01-17

#### JIRA Helper
Improved error logging. The helper now logs meaningful data returned for each error from JIRA.

#### Historical Tracking
Previously, the last\_scan\_data file was not updated until the integration was complete. If the integration failed mid-operation, it would attempt to create tickets for all sites, even if this was previously done before the failure. Each sites' data is now updated after tickets are generated.

#### Bug Fixes
General bug fixes for most classes. Notable listed below

###### Ticket Service
- Not correctly logging errors when the integration failed to load helper and mode classes.
- Missing the site / tag id option when scanning a new asset during a non-initial scan, causing the integration to fail
- Ticket service was calling the incorrect query when closing tickets in Default mode.

###### Ticket Repository
- Method to generate the report in Nexpose was incorreclty applying the site id from the ticket\_service.config file, rather than the value passed in. This may have resulted in an asset in a tag group not being correctly scanned.

###### JIRA Helper
- 'Code' error: The create\_tickets method was trying to parse the reponse code from the HTTP response from JIRA. This was causing the integration to fail on success, as the response was not returned from the send\_tickets method on success.

###### ServiceNow Helper
- Helper now retries retrieving sys_id for tickets from ServiceNow and skips if it cannot retrieve it.

###### Ticketing Modes
- References to individual ticketing modes were removed from the ticket\_service and ticket\_repository class. Any reference now occurs in the chosen helper class

###### Queries
- Default mode query issue: The default mode query on a non-initial scan was previously only returning new vulnerabilities from the previous scan - if a site had been scanned more than once since the integration was run, the vulnerabilities would not have had tickets created. This now correctly returns the number of vulnerabilities.



###1.2.0

####Configuration Options
Ticketing mode must be specified using the entire title, rather than a single character. e.g. 'Vulnerability' instead of 'V'
Added the following configuration option:
- log_console - NXLogger also gets printed to the console.

#### Extensibility
Code for the ticket\_service, ticket\_repository and helpers has been refactored to make it easier for the end-user to modify. Classes listed below now provide common functionality across different implementations.

###### Ticketing Modes
- Ticketing modes (Default, IP, Vulnerability) are now abstracted into their own classes.
- CommonHelper has been replaced with BaseMode from which other modes are extended.

###### Ticketing Helpers
- Ticketing helpers extend a BaseHelper class.
- Ticketing helpers now log the number of tickets that are opened/closed/updated.
- Helpers now support all ticketing modes

###1.1.0
10-02-2016

##### Configuration
Added the following configuration options:
- max_ticket_length - Specifies a maximum length for the description field of a ticket.
- max_title_length - Specifies a maximum length for the title of a ticket.
- max_num_refs - Specifies the maximum number of references included in a vulnerability description.

###1.0.2
08-02-2016

Encoding is now enforced as UTF-8 when parsing CSV files - fixes environment-specific errors.

##### Jira Helper:
- Non-200 return codes are now logged when creating or updating tickets.

##### NX Logger:
- Fixed Windows-specific, input-related errors.

##### ServiceNow:
- No longer queries for existing incident if ticket is new.

###1.0.1
19-01-2016

##### ServiceNow Helper:
- New update set.
- Not backward-compatible with previous update set.
- Incident table now has NXID and Rapid7 ID columns.
- Data is queried from the incident table.
- Updates/creates entries based on a coalesce value rather than sysparm_query.

##### NX Logger:
- Log level set as 'info' for default value.

##### Ticket Service:
- Ticket batching ensures a single ticket is not spread across multiple batches.

##### Report Helper:
- Temp report is flushed before being returned (preventing some timing-based issues).

###1.0.0
10-12-2015

##### Queries:
- Fixed issue where only first source/reference pair was returned.
- Fixed issue where only single solution may be returned.
- Fixed issue where results would be omitted if they lacked references.
- Added hostname information.

- old\_vulns\_since\_scan
  old\_tickets\_by\_ip
    - Filters for distinct IP address and vulnerability ID pairs.

- all\_new\_vulns
  all\_vulns\_since\_scan
    - Filters for distinct IP address and vulnerability ID pairs.
    - Summary row replaced with "solutions" row containing all solutions to each row's vulnerability.

- all\_new\_vulns\_by\_vuln\_id
  new\_vulns\_since\_scan
  new\_vulns\_by\_vuln\_id\_since\_scan
  all\_vulns\_by\_vuln\_id\_since\_scan
    - Vulnerabilities condensed into a single row per vuln ID and comparison status with aggregated columns for assets and solutions.
    - Summary row replaced with "solutions" row containing all solutions to each row's vulnerability.

##### Remedy Helper:
- NXID and ticket description generation moved to CommonHelper class.
- Savon client generation refactored into method.
- Update/close/create ticket sending refactored into new method.
- Added extra information to tickets (parity with Jira)
- Logic for create/update methods consolidated into single prepare_tickets method.
- Queries for tickets updated so that only active tickets are returned.
- Generates valid tickets for new machines which appear in noninitial scans.
- Method "extract_queried_incident" refactored.
    - Closed tickets should be already prevented via the updated query logic.
    - In the "prepare_tickets" method, the results are already filtered down to active tickets, therefore if multiple tickets are found it's an automatic failure.
- Method "ticket_from_queried_incident" introduced to consolidate filling out ticket information (from "extract_queried_incident" and "prepare_close_tickets")
- Hostname information added to vulnerability mode tickets.

##### ServiceNow Helper:
- Vulnerability mode implemented.
- NXID and ticket description generation moved to CommonHelper class.
- Logic for create/update methods consolidated into single prepare_tickets method.
- Added extra information to tickets (parity with Jira)
- Queries for tickets updated so that only active tickets are returned.
- Generates valid tickets for new machines which appear in noninitial scans.

##### ServiceDesk Helper:
- Vulnerability mode implemented.
- NXID and ticket description generation moved to CommonHelper class.
- Added extra information to tickets (parity with Jira)
- Logic for create/update methods consolidated into single prepare_tickets method.
- Ticket update/creation logic updated to account for ticket being built up over multiple rows.

##### JiraHelper:
- Vulnerability mode implemented.
- NXID and ticket description generation moved to CommonHelper class.
- Logic for create/update methods consolidated into single prepare_tickets method.
- Fixed issue where fields could be emptied on ticket update.

##### CommonHelper:
- New class for NXID generation and ticket formatting.
