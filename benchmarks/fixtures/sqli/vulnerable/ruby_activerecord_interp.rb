# Fixture: rb-ar-where-interp + rb-ar-order-param — ActiveRecord injection
# Expected: TRUE POSITIVE (high confidence)
# CWE: CWE-89
# Pattern: String interpolation in where(), user-controlled order()

class UsersController < ApplicationController
  # VULNERABLE: String interpolation in where
  def search
    query = params[:q]
    @users = User.where("email LIKE '%#{query}%'")
    render json: @users
  end

  # VULNERABLE: User-controlled ORDER BY
  def index
    sort = params[:sort]
    @users = User.order(sort)
    render json: @users
  end

  # VULNERABLE: String interpolation in find_by_sql
  def lookup
    name = params[:name]
    @users = User.find_by_sql(
      "SELECT * FROM users WHERE name = '#{name}'"
    )
    render json: @users
  end
end
