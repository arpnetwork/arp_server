defmodule ARP.API.HTTP.Router do
  @moduledoc """
  Define routes.
  """

  alias Plug.Conn.Status

  alias ARP.Admin
  alias ARP.API.HTTP.Response

  use Plug.Router
  use Plug.ErrorHandler

  require Logger

  @skip_token_verification %{joken_skip: true}

  plug(:match)
  plug(Joken.Plug, verify: &ARP.API.HTTP.Router.verify_token/0)
  plug(Plug.Parsers, parsers: [:json], pass: ["application/json"], json_decoder: Poison)
  plug(:dispatch)

  get "/admin/address", private: @skip_token_verification do
    res = Admin.get_address()
    Response.render(conn, res)
  end

  post "/admin/import", private: @skip_token_verification do
    res =
      with :ok <- Admin.import_keystore(conn.params["keystore"], conn.params["password"]) do
        {:ok, %{token: sign_token()}}
      end

    Response.render(conn, res)
  end

  post "/admin/verify", private: @skip_token_verification do
    res =
      with :ok <- Admin.verify_password(conn.params["password"]) do
        {:ok, %{token: sign_token()}}
      end

    Response.render(conn, res)
  end

  post "/admin/config" do
    res = Admin.set_config(conn.params)
    Response.render(conn, res)
  end

  get "/admin/config" do
    res = Admin.get_external_config()
    Response.render(conn, res)
  end

  get "/admin/status" do
    res = Admin.status()
    Response.render(conn, res)
  end

  post "/admin/start" do
    res = Admin.start()
    Response.render(conn, res)
  end

  post "/admin/stop" do
    res = Admin.stop()
    Response.render(conn, res)
  end

  post "/admin/unregister" do
    res = Admin.unregister()
    Response.render(conn, res)
  end

  get "/admin/account" do
    res = Admin.account()
    Response.render(conn, res)
  end

  get "/admin/deviceList" do
    res = Admin.device_list(conn.params["type"])
    Response.render(conn, res)
  end

  get "/admin/deviceDetail" do
    res = Admin.device_detail(conn.params["address"])
    Response.render(conn, res)
  end

  get "/admin/devicePromiseList" do
    res = Admin.device_promise_list()
    Response.render(conn, res)
  end

  get "/admin/dappList" do
    res = Admin.dapp_list()
    Response.render(conn, res)
  end

  get "/admin/dappDetail" do
    res = Admin.dapp_detail(conn.params["address"])
    Response.render(conn, res)
  end

  get "/admin/dappPromiseList" do
    res = Admin.dapp_promise_list()
    Response.render(conn, res)
  end

  post "/admin/cashPromise" do
    res = Admin.cash_dapp_promise(conn.params["address"])
    Response.render(conn, res)
  end

  match _ do
    send_resp(conn, :not_found, "Not Found")
  end

  def handle_errors(conn, %{kind: _kind, reason: _reason, stack: _stack}) do
    Logger.warn("Sent #{conn.status}")
    send_resp(conn, conn.status, Status.reason_phrase(conn.status))
  end

  def verify_token do
    Joken.token()
    |> Joken.with_signer(Joken.hs256(Admin.get_secret()))
    |> Joken.with_sub(Admin.get_address())
  end

  def sign_token do
    Joken.token()
    |> Joken.with_signer(Joken.hs256(Admin.get_secret()))
    |> Joken.sign()
    |> Joken.get_compact()
  end
end
