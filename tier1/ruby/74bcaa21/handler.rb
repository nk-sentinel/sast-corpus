require_relative 'runner'

class ReportsController < ActionController::Base
  def show
    render plain: archive(params[:name].to_s)
  end
end
