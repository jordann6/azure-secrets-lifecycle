# frozen_string_literal: true

# Nothing in this application accepts a parameter that could hold a secret,
# and the dashboard has no forms at all. The filter is here anyway because
# the cost of being wrong about that is the one failure mode this project
# exists to prevent.
Rails.application.config.filter_parameters += %i[
  passw email secret token _key crypt salt certificate otp ssn
  value client_secret connection_string sas
]
