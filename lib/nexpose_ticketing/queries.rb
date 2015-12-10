module NexposeTicketing
  # This class serves as repository of SQL queries
  # to be executed by the SQL Repository Exporter
  # for Nexpose.
  # Copyright:: Copyright (c) 2014 Rapid7, LLC.
  module Queries

    # Formats SQL query for riskscore based on user config options.
	#
    # * *Args*    :
    #   - +riskScore+ -  riskscore for assets to match in results of query.
    #
    # * *Returns* :
    #   - Returns String - Formatted SQL string for inserting into queries.
    #
    def self.createRiskString(riskScore)
      if riskScore.nil?
        riskString = ""
      else
        riskString = "WHERE fa.riskscore >= #{riskScore}"
      end
      return riskString
    end

    # Formats SQL query for filtering per asset based on user config options.
	#
    # * *Args*    :
    #   - +options+ -  User configured options for the ticketing service.
    #
    # * *Returns* :
    #   - Returns String - Formatted SQL string for inserting into queries.
    #

    def self.createAssetString(options)
      if options[:tag_run] && options[:nexpose_item]
        assetString = "WHERE asset_id = #{options[:nexpose_item]}"
      else
        assetString = ""
      end
      return assetString
    end

    # Gets all the latest scans for sites.
    # Returns |site.id| |last_scan_id| |finished|
    def self.last_scans
      'SELECT ds.site_id, ds.last_scan_id, dsc.finished
        FROM dim_site ds
        JOIN dim_scan dsc ON ds.last_scan_id = dsc.scan_id'
    end

    # Gets all the latest scans for tags.
    # Returns |tag.id| |asset.id| |last_scan_id| |finished|
    def self.last_tag_scans
    'select dta.tag_id, dta.asset_id, fa.last_scan_id, fa.scan_finished
      from dim_tag_asset dta
      join fact_asset fa using (asset_id)
      order by dta.tag_id, dta.asset_id, fa.last_scan_id, fa.scan_finished'
    end

    # Gets all delta vulns for all sites sorted by IP.
    #
    # * *Returns* :
    #   -Returns |asset_id| |ip_address| |current_scan|  |vulnerability_id||solution_id| |nexpose_id| 
    #    |url| |summary| |fix|
    #
    def self.all_new_vulns(options = {})
      "SELECT DISTINCT on (da.ip_address, subs.vulnerability_id) subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id, 
       string_agg(DISTINCT 'Summary: ' || coalesce(ds.summary, 'None') ||
                           '|Nexpose ID: ' || ds.nexpose_id ||
                           '|Fix: ' || coalesce(proofAsText(ds.fix), 'None') ||
                           '|URL: ' || coalesce(ds.url, 'None'), '~') as solutions,
       fa.riskscore, dv.cvss_score,
       string_agg(DISTINCT dvr.source || ': ' || dvr.reference, ', ') as references,
        fasva.first_discovered, fasva.most_recently_discovered
        FROM (SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN
          (
            SELECT asset_id, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
              FROM dim_asset #{createAssetString(options)}) s
              ON s.asset_id = fasv.asset_id AND (fasv.scan_id = s.baseline_scan OR fasv.scan_id = s.current_scan)
              GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan, fasv.scan_id
              HAVING NOT baselineComparison(fasv.scan_id, current_scan) = 'Old'
          ) subs
          JOIN dim_vulnerability dv USING (vulnerability_id)
          LEFT JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
          JOIN dim_asset_vulnerability_solution davs USING (vulnerability_id)
          JOIN fact_asset_vulnerability_age fasva ON subs.vulnerability_id = fasva.vulnerability_id AND subs.asset_id = fasva.asset_id
          JOIN dim_solution ds USING (solution_id)
          JOIN dim_asset da ON subs.asset_id = da.asset_id
          JOIN fact_asset fa ON fa.asset_id = da.asset_id
          #{createRiskString( options[:riskScore])}
          GROUP BY subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id, 
                 fa.riskscore, dv.cvss_score, fasva.first_discovered, fasva.most_recently_discovered
          ORDER BY da.ip_address, subs.vulnerability_id"
    end

    # Gets all delta vulns for all sites sorted by vuln ID.
    #
    # * *Returns* :
    #   -Returns |asset_id| |ip_address| |current_scan|  |vulnerability_id||solution_id| |nexpose_id|
    #    |url| |summary| |fix|
    #
    def self.all_new_vulns_by_vuln_id(options = {})
        "SELECT DISTINCT on (subs.vulnerability_id) subs.vulnerability_id, dv.title, MAX(dv.cvss_score) as cvss_score,
                   string_agg(DISTINCT subs.asset_id ||
                     '|' || da.ip_address ||
                     '|' || coalesce(da.host_name, '')  ||
                     '|' || fa.riskscore, '~') as assets,
                 
                   string_agg(DISTINCT 'Summary: ' || coalesce(ds.summary, 'None') ||
                     '|Nexpose ID: ' || ds.nexpose_id ||
                     '|Fix: ' || coalesce(proofAsText(ds.fix)) ||
                     '|URL: ' || coalesce(ds.url, 'None'), '~') as solutions,
         string_agg(DISTINCT dvr.source || ': ' || dvr.reference, ', ') as references
          FROM (SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan
            FROM fact_asset_scan_vulnerability_finding fasv
            JOIN
            (
              SELECT asset_id, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
                FROM dim_asset #{createAssetString(options)}) s
                ON s.asset_id = fasv.asset_id AND (fasv.scan_id = s.baseline_scan OR fasv.scan_id = s.current_scan)
                GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan, fasv.scan_id
                HAVING NOT baselineComparison(fasv.scan_id, current_scan) = 'Old'
            ) subs
          JOIN dim_asset_vulnerability_solution davs USING (vulnerability_id)
          LEFT JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
          JOIN dim_solution ds USING (solution_id)
          JOIN dim_asset da ON subs.asset_id = da.asset_id
          JOIN dim_vulnerability dv ON subs.vulnerability_id = dv.vulnerability_id
          JOIN fact_asset fa ON fa.asset_id = da.asset_id
          JOIN fact_asset_vulnerability_age fasva ON subs.vulnerability_id = fasva.vulnerability_id AND subs.asset_id = fasva.asset_id
          #{createRiskString(options[:riskScore])}
          
          GROUP BY subs.vulnerability_id, dv.title
          ORDER BY subs.vulnerability_id"
    end
    
    # Gets all new vulnerabilities happening after a reported scan id.
    #
    # * *Args*    :
    #   - +reported_scan+ -  Last reported scan id.
    #
    # * *Returns* :
    #   - Returns |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def self.new_vulns_since_scan(options = {})
      "SELECT DISTINCT on (da.ip_address, subs.vulnerability_id) subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id, 
       string_agg(DISTINCT 'Summary: ' || coalesce(ds.summary, 'None') ||
                           '|Nexpose ID: ' || ds.nexpose_id ||
                           '|Fix: ' || coalesce(proofAsText(ds.fix), 'None') ||
                           '|URL: ' || coalesce(ds.url, 'None'), '~') as solutions,
       fa.riskscore, dv.cvss_score,
       string_agg(DISTINCT dvr.source || ': ' || dvr.reference, ', ') as references,
       fasva.first_discovered, fasva.most_recently_discovered
        FROM (SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN
          (
            SELECT asset_id, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
              FROM dim_asset #{createAssetString(options)}) s
              ON s.asset_id = fasv.asset_id AND (fasv.scan_id >=  #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
              GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan
              HAVING baselineComparison(fasv.scan_id, current_scan) = 'New'
          ) subs
      JOIN dim_vulnerability dv USING (vulnerability_id)
      LEFT JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
      JOIN dim_asset_vulnerability_solution davs USING (vulnerability_id)
      JOIN fact_asset_vulnerability_age fasva ON subs.vulnerability_id = fasva.vulnerability_id AND subs.asset_id = fasva.asset_id
      JOIN dim_solution ds USING (solution_id)
      JOIN dim_asset da ON subs.asset_id = da.asset_id
      AND subs.current_scan > #{options[:scan_id]}
      JOIN fact_asset fa ON fa.asset_id = da.asset_id
      #{createRiskString(options[:riskScore])}
      GROUP BY subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id, 
                 fa.riskscore, dv.cvss_score, fasva.first_discovered, fasva.most_recently_discovered
      ORDER BY da.ip_address, subs.vulnerability_id"
    end


    # Gets all new vulnerabilities happening after a reported scan id. Sorted by vuln ID.
    #
    # * *Args*    :
    #   - +reported_scan+ -  Last reported scan id.
    #
    # * *Returns* :
    #   - Returns |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def self.new_vulns_by_vuln_id_since_scan(options = {})
      "SELECT DISTINCT on (subs.vulnerability_id) subs.vulnerability_id, dv.title, MAX(dv.cvss_score) as cvss_score,
                   string_agg(DISTINCT subs.asset_id ||
                     '|' || da.ip_address ||
                     '|' || coalesce(da.host_name, '')  ||
                     '|' || fa.riskscore, '~') as assets,
                 
                   string_agg(DISTINCT 'Summary: ' || coalesce(ds.summary, 'None') ||
                     '|Nexpose ID: ' || ds.nexpose_id ||
                     '|Fix: ' || coalesce(proofAsText(ds.fix)) ||
                     '|URL: ' || coalesce(ds.url, 'None'), '~') as solutions,
         string_agg(DISTINCT dvr.source || ': ' || dvr.reference, ', ') as references
        FROM (SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN
          (
            SELECT asset_id, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
              FROM dim_asset #{createAssetString(options)}) s
              ON s.asset_id = fasv.asset_id AND (fasv.scan_id >=  #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
              GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan
              HAVING baselineComparison(fasv.scan_id, current_scan) = 'New'
          ) subs
      JOIN dim_vulnerability dv USING (vulnerability_id)
      LEFT JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
      JOIN dim_asset_vulnerability_solution davs USING (vulnerability_id)
      JOIN fact_asset_vulnerability_age fasva ON subs.vulnerability_id = fasva.vulnerability_id AND subs.asset_id = fasva.asset_id
      JOIN dim_solution ds USING (solution_id)
      JOIN dim_asset da ON subs.asset_id = da.asset_id
      AND subs.current_scan > #{options[:scan_id]}
      JOIN fact_asset fa ON fa.asset_id = da.asset_id
      #{createRiskString(options[:riskScore])}
      GROUP BY subs.vulnerability_id, dv.title
      ORDER BY vulnerability_id"
    end


    # Gets all old vulnerabilities happening after a reported scan id.
    #
    # * *Args*    :
    #   - +reported_scan+ -  Last reported scan id.
    #
    # * *Returns* :
    #   - Returns |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def self.old_vulns_since_scan(options = {})
      "SELECT DISTINCT on (da.ip_address, subs.vulnerability_id) subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id, dvs.solution_id, ds.nexpose_id, ds.url, 
        proofAsText(ds.summary) as summary, proofAsText(ds.fix) as fix, subs.comparison, fa.riskscore
        FROM (
          SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan, baselineComparison(fasv.scan_id, s.current_scan) as comparison 
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN (
            SELECT asset_id, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
            FROM dim_asset #{createAssetString(options)}
          ) s ON s.asset_id = fasv.asset_id AND (fasv.scan_id >= #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
          GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan
          HAVING baselineComparison(fasv.scan_id, current_scan) = 'Old'
        ) subs
        JOIN dim_vulnerability_solution dvs USING (vulnerability_id)
        JOIN dim_solution ds USING (solution_id)
        JOIN dim_asset da ON subs.asset_id = da.asset_id
        AND subs.current_scan > #{options[:scan_id]}
      	JOIN fact_asset fa ON fa.asset_id = da.asset_id
      	#{createRiskString(options[:riskScore])}
        ORDER BY da.ip_address"
    end


    # Gets all vulnerabilities happening after a reported scan id. This result set also includes the 
    # baseline comparision ("Old", "New", or "Same") allowing for IP-based ticket updating. 
    #
    # * *Args*    :
    #   - +reported_scan+ -  Last reported scan id.
    #
    # * *Returns* :
    #   - Returns |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix| |comparison|
    #
    def self.all_vulns_since_scan(options = {})
      "SELECT DISTINCT on (da.ip_address, subs.vulnerability_id) subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id, 
        string_agg(DISTINCT 'Summary: ' || coalesce(ds.summary, 'None') ||
                           '|Nexpose ID: ' || ds.nexpose_id ||
                           '|Fix: ' || coalesce(proofAsText(ds.fix), 'None') ||
                           '|URL: ' || coalesce(ds.url, 'None'), '~') as solutions, 
        subs.comparison, fa.riskscore, dv.cvss_score, 
        string_agg(DISTINCT dvr.source || ': ' || dvr.reference, ', ') as references,
        null as first_discovered, null as most_recently_discovered
        FROM (
          SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan, baselineComparison(fasv.scan_id, s.current_scan) as comparison
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN (
            SELECT asset_id, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
            FROM dim_asset #{createAssetString(options)}
          ) s ON s.asset_id = fasv.asset_id AND (fasv.scan_id >= #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
          GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan
          HAVING baselineComparison(fasv.scan_id, current_scan) = 'Old'
        ) subs
        JOIN dim_vulnerability dv USING (vulnerability_id)
        LEFT JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
        JOIN dim_vulnerability_solution dvs USING (vulnerability_id)
        JOIN dim_solution ds USING (solution_id)
        JOIN dim_asset da ON subs.asset_id = da.asset_id
        JOIN fact_asset fa ON fa.asset_id = subs.asset_id
         #{createRiskString(options[:riskScore])}
        AND subs.current_scan > #{options[:scan_id]}
        GROUP BY subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id, 
                 fa.riskscore, dv.cvss_score, subs.comparison

        UNION

        SELECT DISTINCT on (da.ip_address, subs.vulnerability_id) subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id,
        string_agg(DISTINCT 'Summary: ' || coalesce(ds.summary, 'None') ||
                           '|Nexpose ID: ' || ds.nexpose_id ||
                           '|Fix: ' || coalesce(proofAsText(ds.fix), 'None') ||
                           '|URL: ' || coalesce(ds.url, 'None'), '~') as solutions, 
        subs.comparison, fa.riskscore, dv.cvss_score, 
        string_agg(DISTINCT dvr.source || ': ' || dvr.reference, ', ') as references,
        fasva.first_discovered, fasva.most_recently_discovered
        FROM 
        (
          SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan, baselineComparison(fasv.scan_id, s.current_scan) as comparison
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN
          (
            SELECT asset_id,lastScan(asset_id) AS current_scan
            FROM dim_asset #{createAssetString(options)}
          ) s ON s.asset_id = fasv.asset_id AND (fasv.scan_id >= #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
          GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan
          HAVING baselineComparison(fasv.scan_id, current_scan) IN ('Same','New')
        ) subs
        JOIN dim_vulnerability dv USING (vulnerability_id)
        LEFT JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
        JOIN dim_asset_vulnerability_solution davs USING (vulnerability_id)
        JOIN fact_asset_vulnerability_age fasva ON subs.vulnerability_id = fasva.vulnerability_id AND subs.asset_id = fasva.asset_id
        JOIN dim_solution ds USING (solution_id)
        JOIN dim_asset da ON subs.asset_id = da.asset_id
        JOIN fact_asset fa ON fa.asset_id = subs.asset_id
        #{createRiskString(options[:riskScore])}
        AND subs.current_scan > #{options[:scan_id]}
        GROUP BY subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id, 
                 fa.riskscore, dv.cvss_score, fasva.first_discovered, fasva.most_recently_discovered, subs.comparison

        ORDER BY ip_address, comparison"
    end

    # Gets all vulnerabilities happening after a reported scan id. Sorted by vuln ID. This result set also includes the
    # baseline comparision ("Old", "New", or "Same") allowing for vulnerability-based ticket updating.
    #
    # * *Args*    :
    #   - +reported_scan+ -  Last reported scan id.
    #
    # * *Returns* :
    #   - Returns |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix| |comparison|
    #
    def self.all_vulns_by_vuln_id_since_scan(options = {})
      "SELECT DISTINCT on (subs.vulnerability_id, subs.comparison) subs.vulnerability_id, dv.title, MAX(dv.cvss_score) as cvss_score,
                   string_agg(DISTINCT subs.asset_id ||
                     '|' || da.ip_address ||
                     '|' || coalesce(da.host_name, '')  ||
                     '|' || fa.riskscore, '~') as assets,
                 
                   string_agg(DISTINCT 'Summary: ' || coalesce(ds.summary, 'None') ||
                     '|Nexpose ID: ' || ds.nexpose_id ||
                     '|Fix: ' || coalesce(proofAsText(ds.fix)) ||
                     '|URL: ' || coalesce(ds.url, 'None'), '~') as solutions,
                   string_agg(DISTINCT dvr.source || ': ' || dvr.reference, ', ') as references,
                   subs.comparison
        FROM (
          SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan, baselineComparison(fasv.scan_id, s.current_scan) as comparison
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN (
            SELECT asset_id, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
            FROM dim_asset #{createAssetString(options)}
          ) s ON s.asset_id = fasv.asset_id AND (fasv.scan_id >= #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
          GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan
          HAVING baselineComparison(fasv.scan_id, current_scan) = 'Old'
        ) subs
        JOIN dim_vulnerability dv USING (vulnerability_id)
        LEFT JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
        JOIN dim_vulnerability_solution dvs USING (vulnerability_id)
        JOIN dim_solution ds USING (solution_id)
        JOIN dim_asset da ON subs.asset_id = da.asset_id
        JOIN fact_asset fa ON fa.asset_id = subs.asset_id
         #{createRiskString(options[:riskScore])}
        AND subs.current_scan > #{options[:scan_id]}
        GROUP BY subs.vulnerability_id, dv.title, subs.comparison

        UNION

        SELECT DISTINCT on (subs.vulnerability_id, subs.comparison) subs.vulnerability_id, dv.title, MAX(dv.cvss_score) as cvss_score,
                   string_agg(DISTINCT subs.asset_id ||
                     '|' || da.ip_address ||
                     '|' || coalesce(da.host_name, '')  ||
                     '|' || fa.riskscore, '~') as assets,
                 
                   string_agg(DISTINCT 'Summary: ' || coalesce(ds.summary, 'None') ||
                     '|Nexpose ID: ' || ds.nexpose_id ||
                     '|Fix: ' || coalesce(proofAsText(ds.fix)) ||
                     '|URL: ' || coalesce(ds.url, 'None'), '~') as solutions,
                   string_agg(DISTINCT dvr.source || ': ' || dvr.reference, ', ') as references,
                   subs.comparison
        FROM 
        (
          SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan, baselineComparison(fasv.scan_id, s.current_scan) as comparison
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN
          (
            SELECT asset_id,lastScan(asset_id) AS current_scan
            FROM dim_asset #{createAssetString(options)}
          ) s ON s.asset_id = fasv.asset_id AND (fasv.scan_id >= #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
          GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan
          HAVING baselineComparison(fasv.scan_id, current_scan) IN ('Same','New')
        ) subs
        JOIN dim_vulnerability dv USING (vulnerability_id)
        LEFT JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
        JOIN dim_asset_vulnerability_solution davs USING (vulnerability_id)
        JOIN dim_solution ds USING (solution_id)
        JOIN dim_asset da ON subs.asset_id = da.asset_id
        JOIN fact_asset fa ON fa.asset_id = subs.asset_id
        #{createRiskString(options[:riskScore])}
        AND subs.current_scan > #{options[:scan_id]}
        GROUP BY subs.vulnerability_id, dv.title, subs.comparison

        ORDER BY vulnerability_id, comparison"
    end


    # Gets all IP addresses that have only old vulnerabilities i.e. any open tickets can be closed.
    #
    # * *Args*    :
    #   - +reported_scan+ -  Last reported scan id.
    #
    # * *Returns* :
    #   - Returns |asset_id| |ip_address| |current_scan| |vulnerability_id| |comparison|
    #
    def self.old_tickets_by_ip(options = {})
      "SELECT DISTINCT on(subs.ip_address) subs.asset_id, subs.ip_address, subs.current_scan, subs.vulnerability_id, subs.comparison
        FROM (
          SELECT fasv.asset_id,  s.ip_address, fasv.vulnerability_id, s.current_scan, baselineComparison(fasv.scan_id, s.current_scan) as comparison
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN (
            SELECT asset_id, ip_address, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
            FROM dim_asset #{createAssetString(options)}
          ) s ON s.asset_id = fasv.asset_id AND (fasv.scan_id >= #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
          GROUP BY fasv.asset_id, fasv.vulnerability_id, s.ip_address, s.current_scan
          HAVING baselineComparison(fasv.scan_id, current_scan) = 'Old'
        ) AS subs
        WHERE subs.ip_address NOT IN (

          SELECT s.ip_address
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN
          (
            SELECT asset_id, ip_address, lastScan(asset_id) AS current_scan
            FROM dim_asset #{createAssetString(options)}
          ) s ON s.asset_id = fasv.asset_id AND (fasv.scan_id >= #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
          GROUP BY s.ip_address, s.current_scan
          HAVING baselineComparison(fasv.scan_id, current_scan) IN ('Same','New')
        )
        AND subs.current_scan > #{options[:scan_id]}
        ORDER BY subs.ip_address"
    end


    # Gets all old vulns that have no active IPs i.e. any open tickets in vuln mode ('V') can be closed.
    #
    # * *Args*    :
    #   - +reported_scan+ -  Last reported scan id.
    #
    # * *Returns* :
    #   - Returns |asset_id| |ip_address| |current_scan| |vulnerability_id| |comparison|
    #
    def self.old_tickets_by_vuln_id(options = {})
      "SELECT subs.vulnerability_id, subs.asset_id, subs.ip_address, subs.current_scan, subs.comparison
        FROM (
          SELECT fasv.asset_id,  s.ip_address, fasv.vulnerability_id, s.current_scan, baselineComparison(fasv.scan_id, s.current_scan) as comparison, fa.riskscore
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN (
            SELECT asset_id, ip_address, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
            FROM dim_asset #{createAssetString(options)}
          ) s ON s.asset_id = fasv.asset_id AND (fasv.scan_id >= #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
      	  JOIN fact_asset fa ON fa.asset_id = fasv.asset_id
      	  #{createRiskString(options[:riskScore])}
          GROUP BY fasv.asset_id, fasv.vulnerability_id, s.ip_address, s.current_scan, fa.riskscore
          HAVING baselineComparison(fasv.scan_id, current_scan) = 'Old'
        ) AS subs
        WHERE subs.vulnerability_id NOT IN (

          SELECT fasv.vulnerability_id
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN
          (
            SELECT da.asset_id, da.ip_address, lastScan(da.asset_id) AS current_scan, fa.riskscore
            FROM dim_asset da #{createAssetString(options)}
      	    JOIN fact_asset fa ON fa.asset_id = da.asset_id
      	    #{createRiskString(options[:riskScore])}
          ) s ON s.asset_id = fasv.asset_id AND (fasv.scan_id >= #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
          GROUP BY fasv.vulnerability_id, s.ip_address, s.current_scan
          HAVING baselineComparison(fasv.scan_id, current_scan) IN ('Same','New')

        )
        AND subs.current_scan > #{options[:scan_id]}
        ORDER BY subs.vulnerability_id"
    end
  end
end
