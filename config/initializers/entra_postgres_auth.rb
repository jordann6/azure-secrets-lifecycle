# frozen_string_literal: true

# Authenticates to Postgres with an Entra ID token instead of a password.
#
# A platform that reports on static credentials should not hold one, and
# the database password is the obvious place a project like this quietly
# keeps one anyway: in a Container App secret, in an environment variable,
# in Key Vault where the app has to be granted read access to fetch it,
# which reopens exactly the hole the Key Vault Reader role was closing.
#
# Azure Database for PostgreSQL Flexible Server accepts an Entra access
# token in place of a password, so there is no password to hold. The token
# lives about an hour, which is why this hooks the client construction
# rather than putting a value in database.yml: every new connection, and
# every reconnect after a pool reap or a failover, mints a fresh one.
#
# Set PGAUTH=entra to enable. Local development and CI leave it unset and
# use a password against the docker-compose Postgres, which has no Entra
# to talk to.

if ENV["PGAUTH"] == "entra"
  ActiveSupport.on_load(:active_record_postgresqladapter) do
    module AzureEntraPostgresAuth
      def new_client(conn_params)
        conn_params = conn_params.dup
        conn_params[:password] = Azure::Token.instance.for(:postgres)
        # Flexible Server matches the connecting principal by name, so the
        # user is the managed identity's display name rather than a
        # database local role.
        conn_params[:user] ||= ENV["PGUSER"]
        super(conn_params)
      end
    end

    ActiveRecord::ConnectionAdapters::PostgreSQLAdapter
      .singleton_class.prepend(AzureEntraPostgresAuth)

    Rails.logger.info("postgres authentication: entra id token, no stored password")
  end
end
