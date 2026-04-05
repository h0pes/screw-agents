# Fixture: Safe parameterized queries — Ruby
# Expected: TRUE NEGATIVE (must NOT be flagged)
# Pattern: ActiveRecord hash conditions, placeholder ?, find/find_by

class SafeUsersController < ApplicationController
  # SAFE: ActiveRecord hash conditions — auto-parameterized
  def search
    query = params[:q]
    @users = User.where(email: query)
    render json: @users
  end

  # SAFE: ActiveRecord where with ? placeholder
  def search_like
    query = params[:q]
    @users = User.where("email LIKE ?", "%#{query}%")
    render json: @users
  end

  # SAFE: ActiveRecord find/find_by — auto-parameterized
  def show
    @user = User.find(params[:id])
    render json: @user
  end

  # SAFE: Allowlisted order
  def index
    allowed = { "name" => "name", "email" => "email", "date" => "created_at" }
    sort = allowed.fetch(params[:sort], "created_at")
    @users = User.order(sort)
    render json: @users
  end

  # SAFE: Arel — type-safe query builder
  def advanced_search
    query = params[:q]
    @users = User.where(User.arel_table[:name].matches("%#{query}%"))
    render json: @users
  end
end
