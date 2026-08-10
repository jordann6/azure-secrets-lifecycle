Rails.application.routes.draw do
  root "dashboard#show"

  resources :scans, only: [:index, :show] do
    member do
      get "evidence"
    end
  end

  get "healthz", to: proc { [200, { "content-type" => "text/plain" }, ["ok"]] }
end
