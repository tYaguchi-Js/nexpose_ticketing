# Nexpose Ticketing Engine.

This is the official gem package for the Ruby Nexpose Ticketing engine.

To share your scripts, or to discuss different approaches, please visit the Rapid7 forums for Nexpose: https://community.rapid7.com/community/nexpose

For assistance with using the gem please email the Rapid7 integrations support team at integrations_support@rapid7.com.

# Usage

To use the JIRA implementation please follow these steps:
* Edit the jira.config file under config and add the necessary data.
* Edit the ticket_service.config file under config and add the necessary data.
* Run the jira file under the bin folder. If installed with Gem 'console> jira' should suffice.

A logger is implemented by default, and the log can be found under the log folder; please refer to the log file in case of an error.


## Contributions

This package is currently a work in progress. Currently there's only a JIRA implementation, with more on the works.

To develop your own implementation for Ticketing service 'foo':

* Create a helper class that implements the following methods:
** create_ticket(tickets) - This method should implement the transport class for the 'foo' service (https, smtp, SOAP, etc).
** prepare_tickets(tickets) - This method will call the selected preparation type: default or ip.
** prepare_tickets_default(vulnerability_list) - This method will take the vulnerability_list in CSV format and transform it into 'foo' accepted data (JSON, XML, etc) per vulnerability.
** prepare_tickets_by_ip(vulnerability_list) - This method will take the vulnerability_list in CSV format and transform it into 'food' accepted data (JSON, XML, etc) collapsing all vulnerabilities by IP.
* Create your 'foo' caller under bin. See the file 'jira' for reference.

Please see jira_helper.rb under helpers for an helper example, and two_vulns_report.csv under the test folder for a sample CSV report.

We welcome contributions to this package. We ask only that pull requests and patches adhere to our coding standards.

* Favor returning classes over key-value maps. Classes tend to be easier for users to manipulate and use.
* Unless otherwise noted, code should adhere to the Ruby Style Guide: https://github.com/bbatsov/ruby-style-guide
* Use YARDoc comment style to improve the API documentation of the gem.
nexpose_ticketing
=================

NexposeTicketing gem. Please do not distribute (yet).
