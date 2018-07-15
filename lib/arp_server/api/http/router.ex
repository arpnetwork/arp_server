defmodule ARP.API.HTTP.Router do
  @moduledoc """
  Define routes.
  """

  use Plug.Router
  use Plug.ErrorHandler

  require Logger

  alias ARP.API.HTTP.Controller
  alias ARP.API.HTTP.Response

  plug(:match)
  plug(Plug.Parsers, parsers: [:json], json_decoder: Poison)
  plug(:dispatch)

  get("/devices/selection", do: Controller.selection(conn))
  post("/users", do: Controller.online(conn, conn.params))
  patch("/users/:user_id", do: Controller.update(conn, conn.params))

  match _ do
    Response.render_error(conn, :not_found)
  end

  def handle_errors(conn, %{kind: _kind, reason: _reason, stack: _stack}) do
    if conn.status do
      Response.render_error(conn, conn.status)
    else
      Response.render_error(conn, :internal_server_error)
    end
  end
end
