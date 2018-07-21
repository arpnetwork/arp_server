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
    |> Conn.send_resp(status, data |> format_data() |> Poison.encode!())
  end

  defp format_data(data) when is_map(data) do
    for {key, val} <- data, into: %{} do
      {first, rest} =
        if(is_atom(key), do: Atom.to_string(key), else: key)
        |> Macro.camelize()
        |> String.split_at(1)

      new_key = String.downcase(first) <> rest

      {new_key, format_data(val)}
    end
  end

  defp format_data(data) do
    data
  end
end
