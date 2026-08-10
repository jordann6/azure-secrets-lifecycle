# frozen_string_literal: true

class ApplicationController < ActionController::Base
  # The dashboard is read only: no forms, no sessions, no state to forge.
  # Nothing here accepts a write, which is why CSRF protection has nothing
  # to protect and is left off rather than configured with no session
  # store behind it.
  protect_from_forgery with: :null_session

  rescue_from ActiveRecord::RecordNotFound, with: :not_found

  private

  def not_found
    render "shared/not_found", status: :not_found, formats: [:html]
  end
end
