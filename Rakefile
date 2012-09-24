require 'rake'

desc 'Install the style into Application Support folder'
task :install do
  directories = ['styles', 'unsupported']

  targets = directories.map { |directory| "#{ENV['HOME']}/Library/Application Support/Propane/#{directory}" }

  # Back up old files
  targets.each do |directory|
    # Only make back ups if these are originals (i.e. no backup exists already)
    if File.exists?(directory) && !File.exists?("#{directory}.backup")
      puts `mv "#{directory}" "#{directory}.backup"`
    end
  end

  # Delete targets and copy new ones to it
  targets.each do |directory|
    FileUtils.rm_rf(directory) if File.exists?(directory)
  end

  directories.each do |directory|
    target = "#{ENV['HOME']}/Library/Application Support/Propane/#{directory}"
    puts `cp -R "$PWD/#{directory}" "#{target}"`
  end
end
