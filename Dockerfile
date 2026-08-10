# One image, two roles. The Container App runs puma to serve the
# dashboard; the scheduled Container Apps Job runs the same image with a
# rake command override. Building once keeps the analyzer the web process
# renders from and the analyzer the schedule runs byte identical.

FROM ruby:3.3.6-slim AS base

ENV RAILS_ENV=production \
    BUNDLE_DEPLOYMENT=1 \
    BUNDLE_PATH=/usr/local/bundle \
    BUNDLE_WITHOUT=development:test \
    RAILS_LOG_TO_STDOUT=1

WORKDIR /app

RUN apt-get update -qq \
    && apt-get install --no-install-recommends -y libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

FROM base AS build

# The production image ships without the development and test groups. The
# docker-compose services target this stage with the arg cleared, so the
# suite runs against the same gem resolution that ships.
ARG BUNDLE_WITHOUT=development:test
ENV BUNDLE_WITHOUT=${BUNDLE_WITHOUT}

RUN apt-get update -qq \
    && apt-get install --no-install-recommends -y build-essential libpq-dev git \
    && rm -rf /var/lib/apt/lists/*

COPY Gemfile Gemfile.lock ./
RUN bundle install \
    && rm -rf "${BUNDLE_PATH}"/ruby/*/cache "${BUNDLE_PATH}"/ruby/*/bundler/gems/*/.git

COPY . .

RUN bundle exec bootsnap precompile app/ lib/

# Asset precompilation must not need a database or any Azure credential.
RUN SECRET_KEY_BASE=precompile-placeholder \
    DATABASE_URL=postgresql://placeholder \
    bundle exec rails assets:precompile

FROM base

COPY --from=build "${BUNDLE_PATH}" "${BUNDLE_PATH}"
COPY --from=build /app /app

# Non root, and no shell for the runtime user. The container holds no
# credential worth stealing, but it does hold a managed identity token
# endpoint, which is worth more.
RUN groupadd --system --gid 1000 rails \
    && useradd --system --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin rails \
    && chown -R rails:rails /app/tmp /app/log 2>/dev/null || true

USER 1000:1000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:3000/healthz || exit 1

ENTRYPOINT ["bundle", "exec"]
CMD ["puma", "-C", "config/puma.rb"]
