# Fixture: ruby-rails-autoescaped — Rails auto-escaping, sanitize(), escape_javascript()
# Expected: TRUE NEGATIVE (must NOT be flagged)
# CWE: CWE-79
# Agent: xss
# Pattern: ERB <%= %> auto-escapes (since Rails 3), sanitize() for safe HTML subsets, escape_javascript()

class CommentsController < ApplicationController
  # SAFE: Rails auto-escapes all strings in ERB templates by default (since Rails 3)
  # Template: <%= @comment.body %> auto-escapes <, >, &, ", '
  # Input "<script>alert(1)</script>" renders as "&lt;script&gt;alert(1)&lt;/script&gt;"
  def show
    @comment = Comment.find(params[:id])
    # No html_safe, no raw() — Rails auto-escaping is active
    # Template uses: <%= @comment.body %> which is auto-escaped
  end

  # SAFE: sanitize() strips dangerous tags while allowing safe HTML subset
  # sanitize() is Rails' built-in HTML sanitizer — it uses a whitelist approach
  def preview
    content = params[:content]

    # SAFE: sanitize() strips <script>, event handlers, etc.
    # Only allows safe tags like <p>, <br>, <strong>, <em>, <ul>, <li>
    @preview_html = ActionController::Base.helpers.sanitize(
      content,
      tags: %w[p br strong em ul ol li a],
      attributes: %w[href title]
    )
  end

  # SAFE: escape_javascript() (alias: j()) for embedding in script contexts
  # Used when user data needs to go inside a <script> block
  def notification
    @message = params[:message]
    # In the template:
    # <script>
    #   var message = "<%= j(@message) %>";
    # </script>
    # escape_javascript() escapes ', ", newlines, and </script> sequences
  end

  # SAFE: content_tag with auto-escaped content
  def banner
    message = params[:message]
    alert_type = params[:type] || "info"

    # SAFE: content_tag auto-escapes the content (second argument)
    @banner = content_tag(:div, message, class: "alert alert-#{alert_type}")
  end
end

# ERB template reference:
#
# SAFE: <%= @variable %> is auto-escaped (this is the default output tag)
# <%= @comment.body %>
#
# SAFE: sanitize helper in template
# <%= sanitize @user.bio %>
#
# SAFE: escape_javascript in script context
# <script>var name = "<%= j(@user.name) %>";</script>
