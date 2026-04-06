# Fixture: ruby-erb-new — ERB.new() with user input
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-1336
# Agent: ssti
# Pattern: User input passed as template source to ERB.new()

require 'sinatra'
require 'erb'
require 'json'

# VULNERABLE: User-controlled template string passed to ERB.new()
# ERB allows arbitrary Ruby execution via <%= %> tags
# Attacker sends: ?template=<%= `id` %> or ?template=<%= system('cat /etc/passwd') %>
get '/api/render' do
  template_src = params['template'] || '<p>Hello, <%= name %></p>'
  name = params['name'] || 'World'

  # VULNERABLE: user-controlled template_src is the ERB template source
  erb_template = ERB.new(template_src)
  result = erb_template.result_with_hash(name: name)

  content_type :html
  result
end

# VULNERABLE: Custom badge markup from user rendered as ERB
# Attacker sends: POST with body {"markup": "<%= `whoami` %>"}
post '/api/badge' do
  data = JSON.parse(request.body.read)
  markup = data['markup'] || '<span class="badge"><%= label %></span>'
  label = data['label'] || 'Default'
  color = data['color'] || 'blue'

  # VULNERABLE: markup from request body is the template source
  full_template = <<~HTML
    <div class="badge-container" style="background-color: #{color};">
      #{markup}
    </div>
  HTML

  erb_template = ERB.new(full_template)
  result = erb_template.result_with_hash(label: label, color: color)

  content_type :html
  result
end

# VULNERABLE: Report header from user input compiled as ERB
# Attacker sends: ?header=<%= IO.read('/etc/passwd') %>
get '/report' do
  header = params['header'] || '<h1><%= title %></h1>'
  title = params['title'] || 'Monthly Report'

  # VULNERABLE: header from query parameter is part of ERB template source
  template_src = <<~HTML
    <html>
    <body>
      <div class="report-header">#{header}</div>
      <div class="report-body">
        <p>Report generated at <%= Time.now %></p>
      </div>
    </body>
    </html>
  HTML

  erb_template = ERB.new(template_src)
  result = erb_template.result_with_hash(title: title)

  content_type :html
  result
end
