def archive(name)
  line = 'tar -cf backup.tar ' + name
  system(line)
end
