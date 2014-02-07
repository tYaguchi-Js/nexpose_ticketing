module NexposeTicketing
  # This class serves as repository of SQL queries
  # to be executed by the SQL Repository Exporter
  # for Nexpose.
  # Copyright:: Copyright (c) 2014 Rapid7, LLC.
  module Queries
    # Gets all the latests scans.
    # Returns |site.id| |last_scan_id| |finished|
    def Queries.last_scans
      'SELECT ds.site_id, ds.last_scan_id, dsc.finished
        FROM dim_site ds
        JOIN dim_scan dsc ON ds.last_scan_id = dsc.scan_id'
    end

    # Gets all delta vulns for all sites.
    # Returns |asset_id| |ip_address| |current_scan|  |vulnerability_id|
    # |solution_id| |nexpose_id| |url| |summary| |fix|
    def Queries.all_delta_vulns
      "SELECT subs.asset_id, da.ip_address, subs.current_scan, subs.vulnerability_id, davs.solution_id, ds.nexpose_id, ds.url,
      proofAsText(ds.summary) as summary, proofAsText(ds.fix) as fix
        FROM (SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN
          (
            SELECT asset_id, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
              FROM dim_asset) s
              ON s.asset_id = fasv.asset_id AND (fasv.scan_id = s.baseline_scan OR fasv.scan_id = s.current_scan)
              GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan
              HAVING baselineComparison(fasv.scan_id, current_scan) = 'New'
          ) subs
        JOIN dim_asset_vulnerability_solution davs USING (vulnerability_id)
        JOIN dim_solution ds USING (solution_id)
        JOIN dim_asset da ON subs.asset_id = da.asset_id
        ORDER BY da.ip_address"
    end

    # Gets all delta vulns happening after reported scan id
    # Returns |asset_id| |ip_address| |current_scan|  |vulnerability_id|
    # |solution_id| |nexpose_id| |url| |summary| |fix|
    def Queries.delta_vulns_since_scan(reported_scan)
      "SELECT subs.asset_id, da.ip_address, subs.current_scan, subs.vulnerability_id, davs.solution_id, ds.nexpose_id, ds.url,
      proofAsText(ds.summary) as summary, proofAsText(ds.fix) as fix
        FROM (SELECT fasv.asset_id, fasv.vulnerability_id, s.current_scan
          FROM fact_asset_scan_vulnerability_finding fasv
          JOIN
          (
            SELECT asset_id, previousScan(asset_id) AS baseline_scan, lastScan(asset_id) AS current_scan
              FROM dim_asset) s
              ON s.asset_id = fasv.asset_id AND (fasv.scan_id > #{reported_scan} OR fasv.scan_id = s.current_scan)
              GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan
              HAVING baselineComparison(fasv.scan_id, current_scan) = 'New'
          ) subs
      JOIN dim_asset_vulnerability_solution davs USING (vulnerability_id)
      JOIN dim_solution ds USING (solution_id)
      JOIN dim_asset da ON subs.asset_id = da.asset_id
      AND subs.current_scan > #{reported_scan}
      ORDER BY da.ip_address"
    end
  end
end
