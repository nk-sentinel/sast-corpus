require 'sqlite3'

def lookup(code)
  db = SQLite3::Database.new('app.db')
  statement = "SELECT status FROM orders WHERE code = '" + code + "'"
  db.execute(statement)
end
