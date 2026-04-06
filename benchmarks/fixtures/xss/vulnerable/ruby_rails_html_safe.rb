# Fixture: ruby-rails-html-safe — Rails html_safe, raw(), and <%== %> patterns
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-79
# Agent: xss
# Pattern: html_safe(), raw(), and <%== %> disable Rails auto-escaping on user-controlled strings

class CommentsController < ApplicationController
  # VULNERABLE: html_safe() marks user-controlled string as safe, bypassing ERB auto-escaping
  # Rails auto-escapes all strings in ERB templates by default (since Rails 3)
  # html_safe() opts the string OUT of this protection
  # Attacker sends: body=<script>alert(document.cookie)</script>
  def show
    comment = Comment.find(params[:id])

    # VULNERABLE: stored user input marked as html_safe
    # Template renders: <%= @comment_body %>
    # Because html_safe was called, Rails skips escaping
    @comment_body = comment.body.html_safe
    @author = comment.author
  end

  # VULNERABLE: raw() helper is equivalent to html_safe()
  # raw() is a view helper that calls to_s.html_safe on its argument
  def preview
    content = params[:content]

    # VULNERABLE: raw() disables escaping for user-controlled input
    # Template: <%= raw(@preview_html) %>
    # Attacker sends: content=<img src=x onerror=alert(1)>
    @preview_html = raw("<div class='preview'>#{content}</div>")
  end

  # VULNERABLE: String interpolation with html_safe on the outer string
  # Even though individual parts might be safe, html_safe on the whole string
  # marks everything (including user input) as safe
  def notification
    message = params[:message]
    alert_type = params[:type] || "info"

    # VULNERABLE: user-controlled message embedded in html_safe'd string
    @notification = "<div class='alert alert-#{alert_type}'>#{message}</div>".html_safe
  end
end

# In the ERB template (comments/show.html.erb), the <%== %> alias is also vulnerable:
#
# <%== @some_user_input %>
#
# <%== %> is an alias for html_safe output — it disables auto-escaping
# This is equivalent to: <%= @some_user_input.html_safe %>
# Developers sometimes use this for "trusted" HTML that is actually user-controlled
