require 'csv'

module NexposeTicketing

class Store
    def initialize()
      @solutions = {}
    end

    # For now we don't cache anything
    def self.store_exists?
      return false
    end

    def set_path(csv_path)
      @csv_path = csv_path
    end

    def fill_store
      # Should this be a single transaction?
      CSV.foreach(@csv_path, headers: true) do |row|
        @solutions[row['solution_id']] = { nexpose_id: row['nexpose_id'],
                                           summary: row['summary'],
                                           fix: row['fix'],
                                           url: row['url'] }
      end
    end

    def get_solution(solution_id)
      @solutions.fetch(solution_id, {})
    end

    def get_solutions(solution_ids)
      sols = []

      solution_ids.each do |s|
        sol = @solutions[s]
        next if sol.nil?
        sols << sol
      end

      sols
    end
  end
end
