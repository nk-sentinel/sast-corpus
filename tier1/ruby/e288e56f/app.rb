require "rack"

App = Rack::CommonLogger.new(lambda do |_env|
  [200, { "content-type" => "text/plain" }, ["ok"]]
end)
