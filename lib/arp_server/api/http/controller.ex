defmodule ARP.API.HTTP.Controller do
  @moduledoc """
  Response the user request.
  """

  alias ARP.API.HTTP.{Error, Response}
  alias ARP.API.TCP.DeviceProtocol
  alias ARP.DeviceManager

  @doc """
  Response the usable devices's attributes.
  """
  def selection(conn) do
    Response.render_success(conn, DeviceManager.selection())
  end

  @doc """
  User online and distribute device according to filters.
  """
  def online(conn, params) do
    filters = params["filters"]
    ip = conn.remote_ip |> Tuple.to_list() |> Enum.join(".")

    user_id = UUID.uuid1()
    session = Base.encode64(:crypto.strong_rand_bytes(96))

    with true <- is_map(filters),
         filters <-
           for({key, val} <- filters, into: %{}, do: {String.to_existing_atom(key), val}),
         {:ok, dev} <- ARP.DeviceManager.request(filters, user_id),
         :ok <- DeviceProtocol.user_request(dev.id, session, ip) do
      Response.render_success(conn, %{
        id: user_id,
        session: session,
        device: Map.take(dev, [:id, :ip, :port])
      })
    else
      {:error, :no_free_device} ->
        Response.render_error(conn, :not_found, Error.new(:no_free_device))

      _ ->
        Response.render_error(conn, :bad_request, Error.new(:invalid_param))
    end
  end

  @doc """
  Update user state.
  """
  def update(conn, params) do
    Response.render_success(conn, params)
  end
end
