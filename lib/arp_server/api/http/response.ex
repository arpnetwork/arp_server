defmodule ARP.API.HTTP.Response do
  @moduledoc """
  Render response.
  """

  alias Plug.Conn
  alias Plug.Conn.Status

  alias ARP.API.HTTP.Error

  @default_content_type "application/json"

  @doc false
  def render(conn, data) do
    render(conn, Status.code(:ok), data)
  end

  @doc false
  def render(conn, status, data) do
    resp_data = data |> gen_resp_data() |> format_data() |> Poison.encode!()

    conn
    |> Conn.put_resp_content_type(@default_content_type)
    |> Conn.send_resp(status, resp_data)
  end

  defp gen_resp_data(data) do
    case data do
      :ok ->
        %{code: 0}

      {:ok, data} ->
        %{code: 0, data: data}

      {:error, code} ->
        Error.new(code)

      d when is_map(d) or is_list(d) ->
        %{code: 0, data: data}

      _ ->
        Error.new(:unknow_error)
    end
  end

  defp format_data(data) when is_map(data) do
    for item <- data, into: %{} do
      format_data(item)
    end
  end

  defp format_data(data) when is_list(data) do
    for item <- data, into: [] do
      format_data(item)
    end
  end

  defp format_data({key, value}) when is_atom(key) do
    format_data({Atom.to_string(key), value})
  end

  defp format_data({key, value}) do
    {first, rest} =
      key
      |> Macro.camelize()
      |> String.split_at(1)

    new_key = String.downcase(first) <> rest

    {new_key, format_data(value)}
  end

  defp format_data(data) do
    data
  end
end
