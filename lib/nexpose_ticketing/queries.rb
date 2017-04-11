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
      return '' if riskScore.nil?

      "WHERE fa.riskscore >= #{riskScore}"
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
        "WHERE asset_id = #{options[:nexpose_item]}"
      else
        ''
      end
    end

    # Gets all the latest scans for sites.
    # Returns |site.id| |last_scan_id| |finished|
    def self.last_scans
      'SELECT ds.site_id, ds.last_scan_id, dsc.finished
        FROM dim_site ds
        JOIN dim_scan dsc ON ds.last_scan_id = dsc.scan_id'
    end

    # Returns the solutions for every vulnerability
    # stored within Nexpose
    def self.all_solutions
      "SELECT solution_id, nexpose_id,
              summary,
              proofAsText(fix) as fix,
              url
       FROM dim_solution"
    end

    # Gets all the latest scans for tags.
    # Returns |tag.id| |asset.id| |last_scan_id| |finished|
    def self.last_tag_scans
    'select dta.tag_id, dta.asset_id, fa.last_scan_id, fa.scan_finished
      from dim_tag_asset dta
      join fact_asset fa using (asset_id)
      order by dta.tag_id, dta.asset_id, fa.last_scan_id, fa.scan_finished'
    end

    # Returns the current necessary information on vulnerable_instances for a
    # site / tag to create a ticket, for IP mode
    # * *Returns* :
    #   - Returns |asset_id| |vulnerability_id| |first_discovered|
    #             |most_recently_discovered| |solution_ids|
    def self.all_new_vulns_by_ip(options={})
      'SELECT asset_id, vulnerability_id,
         first_discovered, most_recently_discovered,
         array_agg(solution_id) as solution_ids
        FROM (
          SELECT asset_id, vulnerability_id
          FROM fact_asset_vulnerability_finding) favf
        JOIN (
          SELECT asset_id, vulnerability_id, first_discovered,
            most_recently_discovered
          FROM fact_asset_vulnerability_age) fava USING (asset_id, vulnerability_id)
        LEFT JOIN dim_asset_vulnerability_solution USING (asset_id, vulnerability_id)
        GROUP BY asset_id, vulnerability_id, first_discovered, most_recently_discovered
        ORDER BY asset_id, vulnerability_id'
    end

    # Returns the current necessary information on vulnerable_instances for a
    # site to creating a ticket, for Vulnerability mode
    # * *Returns* :
    #   - Returns |vulnerability_id| |solution_ids| |references|
    def self.all_new_vulns_by_vuln_id(options={})
      "SELECT DISTINCT(vulnerability_id) vulnerability_id,
         array_agg(DISTINCT solution_id) as solution_ids,
         string_agg(DISTINCT dvr.source || ': ' || dvr.reference, ', ') as references
        FROM (
          SELECT asset_id, vulnerability_id
          FROM fact_asset_vulnerability_finding) favf
        LEFT JOIN dim_asset_vulnerability_solution USING (asset_id, vulnerability_id)
        LEFT JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
        GROUP BY vulnerability_id
        ORDER BY vulnerability_id"
    end

    # Returns information on the previous state of the site / tag, for IP mode
    # * *Returns* :
    #   - Returns |asset_id| |vulnerability_id| |scan_id|
    def self.last_scan_state_by_ip(options={})
      "SELECT asset_id, vulnerability_id, scan_id
       FROM fact_asset_scan_vulnerability_finding
       WHERE scan_id = #{options[:scan_id]}
       ORDER BY asset_id, vulnerability_id"
    end

    # Returns information on the previous state of the site, for Vulnerability
    # mode
    # * *Returns* :
    #   - Returns |vulnerability_id| |asset_ids| |scan_id|
    def self.last_scan_state_by_vuln_id(options={})
      "SELECT DISTINCT(vulnerability_id) vulnerability_id,
        array_agg(DISTINCT asset_id) as asset_ids, scan_id
       FROM fact_asset_scan_vulnerability_finding
       WHERE scan_id = #{options[:scan_id]}
       GROUP BY vulnerability_id, scan_id
       ORDER BY vulnerability_id"
    end

    def self.all_new_vulns_by_ip_solutions(options={})
      'SELECT asset_id, vulnerability_id, summary, fix, url
        FROM (select asset_id, vulnerability_id FROM fact_asset_scan_vulnerability_finding) fasv
        JOIN dim_asset_vulnerability_solution dvs USING (asset_id, vulnerability_id)
        JOIN (select solution_id, summary, fix, url FROM dim_solution) ds USING (solution_id)
        ORDER BY asset_id, vulnerability_id'
    end

    # Gets all delta vulns for all sites sorted by IP.
    #
    # * *Returns* :
    #   -Returns |asset_id| |ip_address| |current_scan|  |vulnerability_id||solution_id| |nexpose_id|
    #    |url| |summary| |fix|
    #
    def self.all_new_vulns_by_ip_old(options = {})
      "SELECT asset_id, vulnerability_id, ip_address, riskscore, nexpose_id, cvss_score,
                first_discovered, most_recently_discovered,
                array_agg(solution_id) as solution_ids
      FROM (SELECT asset_id, vulnerability_id FROM fact_asset_vulnerability_finding) favf
      JOIN (SELECT vulnerability_id, nexpose_id, cvss_score FROM dim_vulnerability) dv USING (vulnerability_id)
      JOIN (SELECT asset_id, vulnerability_id, first_discovered, most_recently_discovered FROM fact_asset_vulnerability_age) fava USING (asset_id, vulnerability_id)
      JOIN (SELECT asset_id, ip_address FROM dim_asset) da USING (asset_id)
      JOIN (SELECT asset_id, riskscore FROM fact_asset) fa USING (asset_id)
      JOIN dim_asset_vulnerability_solution USING (asset_id, vulnerability_id)
      #{createAssetString(options)}
      #{createRiskString( options[:riskScore])}
      GROUP BY asset_id, vulnerability_id, ip_address, riskscore, nexpose_id, cvss_score,
               first_discovered, most_recently_discovered
      ORDER BY asset_id, vulnerability_id"
    end

    # Gets all delta vulns for all sites sorted by vuln ID.
    #
    # * *Returns* :
    #   -Returns |asset_id| |ip_address| |current_scan|  |vulnerability_id||solution_id| |nexpose_id|
    #    |url| |summary| |fix|
    #
    def self.all_new_vulns_by_vuln_id_old(options = {})
        "SELECT DISTINCT on (subs.vulnerability_id) subs.vulnerability_id, dv.nexpose_id as vuln_nexpose_id, dv.title, MAX(dv.cvss_score) as cvss_score,
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
          
          GROUP BY subs.vulnerability_id, dv.title, dv.nexpose_id
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
    def self.new_vulns_since_scan_by_ip(options = {})
      "SELECT fin.asset_id, fin.ip_address, fin.host_name, fin.current_scan, 
      fin.vulnerability_id, fin.vuln_nexpose_id,
      string_agg(DISTINCT 'Summary: ' || coalesce(ds.summary, 'None') ||
                          '|Nexpose ID: ' || ds.nexpose_id ||
                          '|Fix: ' || coalesce(proofAsText(ds.fix), 'None') ||
                          '|URL: ' || coalesce(ds.url, 'None'), '~') as solutions,
      fin.riskscore, fin.cvss_score, fin.references, 
      fin.first_discovered, fin.most_recently_discovered
      FROM(
        SELECT scns.asset_id, scns.ip_address, scns.host_name, scns.current_scan, 
        scns.scan_id, scns.vulnerability_id, dv.nexpose_id as vuln_nexpose_id,
        fa.riskscore, dv.cvss_score, 
        string_agg(DISTINCT dvr.source || ': ' || dvr.reference, ', ') as references, 
        fasva.first_discovered, fasva.most_recently_discovered
        FROM(
          SELECT subs.asset_id, subs.ip_address, subs.host_name, 
          subs.vulnerability_id, subs.scan_id, subs.current_scan
          FROM(
            SELECT DISTINCT on (fasv.asset_id, fasv.vulnerability_id) 
            fasv.asset_id, fasv.vulnerability_id, s.ip_address, s.host_name, 
            fasv.scan_id, s.current_scan
            FROM fact_asset_scan_vulnerability_finding fasv
            JOIN (
              SELECT asset_id, ip_address, host_name, 
              lastScan(asset_id) AS current_scan
              FROM dim_asset #{createAssetString(options)}
            ) s
            ON s.asset_id = fasv.asset_id AND 
            (fasv.scan_id >= #{options[:scan_id]} OR fasv.scan_id = s.current_scan)
            WHERE s.current_scan > #{options[:scan_id]}
            GROUP BY fasv.asset_id, fasv.vulnerability_id, s.ip_address, 
            s.host_name, fasv.scan_id, s.current_scan
            ORDER BY fasv.asset_id, fasv.vulnerability_id, s.ip_address, 
            s.host_name, fasv.scan_id
          )subs
          WHERE subs.scan_id > #{options[:scan_id]}
        )scns
        JOIN dim_vulnerability dv USING (vulnerability_id)
        LEFT JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
        JOIN fact_asset_vulnerability_age fasva ON 
        scns.vulnerability_id = fasva.vulnerability_id AND 
        scns.asset_id = fasva.asset_id
        JOIN fact_asset fa ON fa.asset_id = scns.asset_id
        #{createRiskString(options[:riskScore])}
        GROUP BY scns.asset_id, scns.ip_address, scns.host_name, 
        scns.current_scan, scns.vulnerability_id, dv.nexpose_id, fa.riskscore, 
        dv.cvss_score, scns.scan_id, fasva.first_discovered, 
        fasva.most_recently_discovered
      )fin
      JOIN dim_asset_vulnerability_solution davs USING (vulnerability_id)
      JOIN dim_solution ds USING (solution_id)
      GROUP BY fin.asset_id, fin.ip_address, fin.host_name, fin.current_scan, 
      fin.vulnerability_id, fin.vuln_nexpose_id, fin.riskscore, fin.cvss_score, 
      fin.scan_id, fin.references, fin.first_discovered, fin.most_recently_discovered
      ORDER BY fin.ip_address, fin.vulnerability_id"
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
    def self.new_vulns_since_scan_by_vuln_id(options = {})
      "SELECT DISTINCT on (subs.vulnerability_id) subs.vulnerability_id, dv.nexpose_id as vuln_nexpose_id,
       dv.title, MAX(dv.cvss_score) as cvss_score,
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
      GROUP BY subs.vulnerability_id, dv.title, dv.nexpose_id
      ORDER BY vulnerability_id"
    end


    # Gets all old vulnerabilities happening after a reported scan id.
    # Used in default mode to return tickets to close
    #
    # * *Args*    :
    #   - +reported_scan+ -  Last reported scan id.
    #
    # * *Returns* :
    #   - Returns |asset_id| |ip_address| |current_scan| |vulnerability_id| |solution_id| |nexpose_id|
    #     |url| |summary| |fix|
    #
    def self.old_vulns_since_scan_by_ip(options = {})
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
    def self.all_vulns_since_scan_by_ip(options = {})
      "SELECT DISTINCT on (da.ip_address, subs.vulnerability_id) subs.asset_id, da.ip_address, da.host_name, subs.current_scan, 
        subs.vulnerability_id, dv.nexpose_id as vuln_nexpose_id,
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
        GROUP BY subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id, dv.nexpose_id,
                 fa.riskscore, dv.cvss_score, subs.comparison
        UNION
        SELECT DISTINCT on (da.ip_address, subs.vulnerability_id) subs.asset_id, da.ip_address, da.host_name, subs.current_scan, 
        subs.vulnerability_id, dv.nexpose_id as vuln_nexpose_id,
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
        GROUP BY subs.asset_id, da.ip_address, da.host_name, subs.current_scan, subs.vulnerability_id, dv.nexpose_id,
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
    def self.all_vulns_since_scan_by_vuln_id(options = {})
      "SELECT DISTINCT on (subs.vulnerability_id, subs.comparison) subs.vulnerability_id, dv.nexpose_id as vuln_nexpose_id,
       dv.title, MAX(dv.cvss_score) as cvss_score,
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
        GROUP BY subs.vulnerability_id, dv.title, dv.nexpose_id, subs.comparison

        UNION

        SELECT DISTINCT on (subs.vulnerability_id, subs.comparison) subs.vulnerability_id, dv.nexpose_id as vuln_nexpose_id,
        dv.title, MAX(dv.cvss_score) as cvss_score,
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
        GROUP BY subs.vulnerability_id, dv.title, dv.nexpose_id, subs.comparison

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
      "SELECT DISTINCT on(subs.vulnerability_id) subs.vulnerability_id, subs.asset_id, subs.ip_address, subs.current_scan, subs.comparison
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
