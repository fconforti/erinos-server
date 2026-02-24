require "sinatra/base"
require "json"
require "net/http"
require "uri"

class Server < Sinatra::Base
  set :host_authorization, permitted_hosts: []

  TTL = 300 # 5 minutes

  RELAY_PUBLIC_URL = ENV.fetch("RELAY_PUBLIC_URL", "https://auth.erinos.net")
  HEADSCALE_URL    = ENV.fetch("HEADSCALE_URL", "http://headscale:8080")
  HEADSCALE_API_KEY = ENV["HEADSCALE_API_KEY"]
  REGISTER_SECRET  = ENV["REGISTER_SECRET"]
  DOMAIN           = ENV.fetch("DOMAIN", "erinos.net")

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

    def headscale_get(path)
      uri = URI("#{HEADSCALE_URL}#{path}")
      req = Net::HTTP::Get.new(uri)
      req["Authorization"] = "Bearer #{HEADSCALE_API_KEY}"
      Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
    end

    def headscale_post(path, body)
      uri = URI("#{HEADSCALE_URL}#{path}")
      req = Net::HTTP::Post.new(uri)
      req["Authorization"] = "Bearer #{HEADSCALE_API_KEY}"
      req["Content-Type"] = "application/json"
      req.body = body.to_json
      Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
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

    halt 503, { error: "registration not configured" }.to_json unless REGISTER_SECRET && HEADSCALE_API_KEY

    body = JSON.parse(request.body.read)
    secret = body["secret"]
    device_name = body["device_name"]

    halt 400, { error: "missing secret or device_name" }.to_json unless secret && device_name
    halt 403, { error: "invalid secret" }.to_json unless Rack::Utils.secure_compare(secret, REGISTER_SECRET)

    # Sanitize device_name: lowercase alphanumeric + hyphens, max 63 chars
    user = device_name.downcase.gsub(/[^a-z0-9-]/, "-").gsub(/-+/, "-").sub(/^-/, "").sub(/-$/, "")[0, 63]
    halt 400, { error: "invalid device_name" }.to_json if user.empty?

    # Ensure Headscale user exists
    unless headscale_get("/api/v1/user/#{user}").is_a?(Net::HTTPSuccess)
      res = headscale_post("/api/v1/user", { name: user })
      halt 502, { error: "failed to create user: #{res.body}" }.to_json unless res.is_a?(Net::HTTPSuccess)
    end

    # Create single-use pre-auth key (1 hour expiry)
    expiration = (Time.now + 3600).utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    res = headscale_post("/api/v1/preauthkey", {
      user: user,
      reusable: false,
      ephemeral: false,
      expiration: expiration
    })
    halt 502, { error: "failed to create preauthkey: #{res.body}" }.to_json unless res.is_a?(Net::HTTPSuccess)

    key_data = JSON.parse(res.body)
    auth_key = key_data.dig("preAuthKey", "key")

    {
      auth_key: auth_key,
      login_server: "https://hs.#{DOMAIN}",
      user: user
    }.to_json
  end

  # Health
  get "/health" do
    content_type :json
    { status: "ok" }.to_json
  end
end
