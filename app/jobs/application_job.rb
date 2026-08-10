# frozen_string_literal: true

class ApplicationJob < ActiveJob::Base
  # Azure throttles Graph and Key Vault aggressively enough that a whole
  # scan can lose to a burst that would have cleared in seconds.
  retry_on Azure::Client::Error, wait: :polynomially_longer, attempts: 3

  discard_on ActiveJob::DeserializationError
end
