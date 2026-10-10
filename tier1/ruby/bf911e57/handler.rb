require_relative 'store'

class ReportsController < ActionController::Base
  def show
    render plain: lookup(params[:code].to_s)
  end
end
