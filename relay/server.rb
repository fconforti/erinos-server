require "sinatra/base"
require "json"

class Server < Sinatra::Base
  # Auth relay
  get "/oauth/start" do
    content_type :json
    status 501
    { todo: "Redirect to OAuth provider" }.to_json
  end

  get "/oauth/callback" do
    content_type :json
    status 501
    { todo: "Receive code, store state → code mapping" }.to_json
  end

  get "/oauth/poll/:state" do
    content_type :json
    status 501
    { todo: "Return code or 202/410" }.to_json
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
