require "sinatra/base"
require "json"

class Server < Sinatra::Base
  TTL = 300 # 5 minutes

  set :oauth_store, {}

  helpers do
    def oauth_store
      settings.oauth_store
    end

    def purge_expired
      oauth_store.delete_if { |_, v| Time.now - v[:created_at] > TTL }
    end
  end

  # Auth relay
  get "/oauth/start" do
    authorize_url = params["authorize_url"]
    state = params["state"]

    halt 400, { "Content-Type" => "application/json" }, { error: "missing authorize_url and state" }.to_json unless authorize_url && state
    halt 400, { "Content-Type" => "application/json" }, { error: "authorize_url must be https" }.to_json unless authorize_url.start_with?("https://")

    purge_expired
    oauth_store[state] = { status: :pending, created_at: Time.now }

    redirect authorize_url, 302
  end

  get "/oauth/callback" do
    code = params["code"]
    state = params["state"]

    halt 400, { "Content-Type" => "text/html" }, "Missing code or state." unless code && state
    halt 400, { "Content-Type" => "text/html" }, "Unknown state." unless oauth_store.key?(state)

    oauth_store[state] = { status: :complete, code: code, created_at: Time.now }

    content_type :html
    "<!DOCTYPE html><html><body><p>Authorization complete. You can close this tab.</p></body></html>"
  end

  get "/oauth/poll/:state" do
    content_type :json
    state = params["state"]
    entry = oauth_store[state]

    halt 404, { error: "not_found" }.to_json unless entry

    if Time.now - entry[:created_at] > TTL
      oauth_store.delete(state)
      halt 410, { error: "expired" }.to_json
    end

    if entry[:status] == :complete
      code = entry[:code]
      oauth_store.delete(state)
      { code: code }.to_json
    else
      status 202
      { status: "pending" }.to_json
    end
  end

  # Registration
  post "/register" do
    content_type :json
    status 501
    { todo: "Create Headscale user + pre-auth key" }.to_json
  end

  # Health
  get "/health" do
    content_type :json
    { status: "ok" }.to_json
  end
end
