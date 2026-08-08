def archive(name)
  system('tar', '-cf', 'backup.tar', name)
end
