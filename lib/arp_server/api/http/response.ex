defmodule ARP.API.HTTP.Response do
  @moduledoc """
  Render response.
  """

  alias Plug.Conn
  alias ARP.API.HTTP.Error

  @default_content_type "application/json"

  @doc false
  def render_success(conn, data) when is_map(data) or is_list(data) do
    render(conn, Conn.Status.code(:ok), data)
  end

  @doc false
  def render_error(conn, status, error \\ nil) do
    status =
      if is_atom(status) do
        Conn.Status.code(status)
      else
        status
      end

    error =
      if is_nil(error) do
        Error.new(:other_error, Conn.Status.reason_phrase(status))
      else
        error
      end

    render(conn, status, error)
  end

  @doc false
  def render(conn, status, data) do
    conn
    |> Conn.put_resp_content_type(@default_content_type)
    |> Conn.send_resp(status, Poison.encode!(data))
  end
end
