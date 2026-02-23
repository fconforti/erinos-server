require "sinatra/base"
require "json"
require "net/http"
require "uri"

class Server < Sinatra::Base
  set :host_authorization, permitted_hosts: []

  TTL = 300 # 5 minutes

  RELAY_PUBLIC_URL = ENV.fetch("RELAY_PUBLIC_URL", "https://auth.erinos.net")

  PROVIDERS = {
    "spotify" => {
      authorize_url: "https://accounts.spotify.com/authorize",
      token_url: "https://accounts.spotify.com/api/token",
      client_id: ENV["SPOTIFY_CLIENT_ID"],
      client_secret: ENV["SPOTIFY_CLIENT_SECRET"],
      scopes: "user-read-playback-state user-modify-playback-state user-read-currently-playing playlist-read-private playlist-read-collaborative playlist-modify-public playlist-modify-private"
    },
    "google" => {
      authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
      token_url: "https://oauth2.googleapis.com/token",
      client_id: ENV["GOOGLE_CLIENT_ID"],
      client_secret: ENV["GOOGLE_CLIENT_SECRET"],
      scopes: "https://www.googleapis.com/auth/calendar",
      extra_params: { access_type: "offline", prompt: "consent" }
    }
  }.freeze

  set :oauth_store, {}

  helpers do
    def oauth_store
      settings.oauth_store
    end

    def purge_expired
      oauth_store.delete_if { |_, v| Time.now - v[:created_at] > TTL }
    end
  end

  # Provider-specific OAuth start
  get "/oauth/:provider/start" do
    provider = params["provider"]
    config = PROVIDERS[provider]
    halt 404, { "Content-Type" => "application/json" }, { error: "unknown provider" }.to_json unless config
    halt 500, { "Content-Type" => "application/json" }, { error: "provider not configured" }.to_json unless config[:client_id]

    state = params["state"]
    halt 400, { "Content-Type" => "application/json" }, { error: "missing state" }.to_json unless state

    purge_expired
    oauth_store[state] = { provider: provider, status: :pending, created_at: Time.now }

    query_params = {
      client_id: config[:client_id],
      response_type: "code",
      redirect_uri: "#{RELAY_PUBLIC_URL}/oauth/callback",
      scope: config[:scopes],
      state: state
    }
    query_params.merge!(config[:extra_params]) if config[:extra_params]
    query = URI.encode_www_form(query_params)

    redirect "#{config[:authorize_url]}?#{query}", 302
  end

  get "/oauth/callback" do
    code = params["code"]
    state = params["state"]

    halt 400, { "Content-Type" => "text/html" }, "Missing code or state." unless code && state
    halt 400, { "Content-Type" => "text/html" }, "Unknown state." unless oauth_store.key?(state)

    entry = oauth_store[state]
    config = PROVIDERS[entry[:provider]]

    # Exchange authorization code for tokens
    uri = URI(config[:token_url])
    res = Net::HTTP.post_form(uri, {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: "#{RELAY_PUBLIC_URL}/oauth/callback",
      client_id: config[:client_id],
      client_secret: config[:client_secret]
    })
    tokens = JSON.parse(res.body)

    if res.is_a?(Net::HTTPSuccess)
      oauth_store[state] = {
        provider: entry[:provider],
        status: :complete,
        tokens: {
          access_token: tokens["access_token"],
          refresh_token: tokens["refresh_token"],
          expires_in: tokens["expires_in"]
        },
        created_at: Time.now
      }

      content_type :html
      "<!DOCTYPE html><html><body><p>Authorization complete. You can close this tab.</p></body></html>"
    else
      oauth_store.delete(state)
      content_type :html
      status 502
      "<!DOCTYPE html><html><body><p>Token exchange failed: #{tokens['error_description'] || tokens['error']}</p></body></html>"
    end
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
      tokens = entry[:tokens]
      oauth_store.delete(state)
      tokens.to_json
    else
      status 202
      { status: "pending" }.to_json
    end
  end

  # Provider-specific token refresh
  post "/oauth/:provider/refresh" do
    content_type :json
    provider = params["provider"]
    config = PROVIDERS[provider]
    halt 404, { error: "unknown provider" }.to_json unless config
    halt 500, { error: "provider not configured" }.to_json unless config[:client_secret]

    body = JSON.parse(request.body.read)
    refresh_token = body["refresh_token"]
    halt 400, { error: "missing refresh_token" }.to_json unless refresh_token

    uri = URI(config[:token_url])
    res = Net::HTTP.post_form(uri, {
      grant_type: "refresh_token",
      refresh_token: refresh_token,
      client_id: config[:client_id],
      client_secret: config[:client_secret]
    })
    tokens = JSON.parse(res.body)

    unless res.is_a?(Net::HTTPSuccess)
      halt 502, { error: "refresh failed: #{tokens['error_description'] || tokens['error']}" }.to_json
    end

    {
      access_token: tokens["access_token"],
      refresh_token: tokens["refresh_token"],
      expires_in: tokens["expires_in"]
    }.to_json
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
