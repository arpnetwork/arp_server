defmodule ARP.Device do
  @moduledoc """
  Record online device.
  """

  alias ARP.{DevicePool, DeviceNetSpeed}
  alias ARP.API.TCP.DeviceProtocol

  use GenServer, restart: :temporary

  # state value
  @pending 0
  @idle 1
  @allocating 2

  defstruct [
    :address,
    :price,
    :ip,
    :port,
    :dapp_address,
    :brand,
    :model,
    :cpu,
    :gpu,
    :ram,
    :storage,
    :os_ver,
    :system_ver,
    :width,
    :height,
    :imsi,
    :telecom_operator,
    :connectivity,
    :telephony,
    :upload_speed,
    :download_speed,
    :ver,
    :cid,
    state: @pending
  ]

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  def check_port(ip, tcp_port, http_port) do
    ip_str = ip |> Tuple.to_list() |> Enum.join(".")

    with {:ok, socket} <- :gen_tcp.connect(ip, tcp_port, [active: false], 5000),
         {{:ok, data}, _} when data == [0, 0, 0, 0] <- {:gen_tcp.recv(socket, 4, 5000), socket},
         :gen_tcp.close(socket),
         JSONRPC2.Client.HTTP.call("http://#{ip_str}:#{http_port}", "device_ping", []),
         {:ok, _} <- JSONRPC2.Client.HTTP.call("http://#{ip_str}:#{http_port}", "device_ping", []) do
      :ok
    else
      {{_, _}, socket} ->
        :gen_tcp.close(socket)
        :error

      _ ->
        :error
    end
  end

  def offline(pid, dev) do
    if pid && Process.alive?(pid) do
      GenServer.call(pid, {:offline, dev})
    else
      {:error, :invalid_pid}
    end
  end

  def release(pid, address, dapp_address) do
    if Process.alive?(pid) do
      GenServer.cast(pid, {:release, address, dapp_address})
    else
      {:error, :invalid_pid}
    end
  end

  def idle(pid) do
    if Process.alive?(pid) do
      GenServer.call(pid, :idle)
    else
      {:error, :invalid_pid}
    end
  end

  def update_net_speed(pid, upload_speed, download_speed) do
    if Process.alive?(pid) do
      GenServer.call(pid, {:update_net_speed, upload_speed, download_speed})
    else
      {:error, :invalid_pid}
    end
  end

  def allocating(pid, dapp_address) do
    if Process.alive?(pid) do
      GenServer.call(pid, {:allocating, dapp_address})
    else
      {:error, :invalid_pid}
    end
  end

  ## Callbacks

  def init(opts) do
    dev = opts[:device]

    if dev.state == @pending do
      DeviceNetSpeed.online(dev.ip, dev.address)
    end

    {:ok, %{address: dev.address}}
  end

  def handle_call({:offline, dev}, _from, %{address: address} = state) do
    DevicePool.delete(address)

    if dev do
      DeviceNetSpeed.offline(dev.ip, address)
    end

    {:stop, :normal, :ok, state}
  end

  def handle_call(:idle, _from, %{address: address} = state) do
    case DevicePool.get(address) do
      {_pid, dev} ->
        dev = set_idle(dev)
        DevicePool.update(address, dev)
        {:reply, :ok, state}

      _ ->
        {:reply, {:error, :device_not_found}, state}
    end
  end

  def handle_call(
        {:update_net_speed, upload_speed, download_speed},
        _from,
        %{address: address} = state
      ) do
    case DevicePool.get(address) do
      {_pid, dev} ->
        dev = %{dev | upload_speed: upload_speed, download_speed: download_speed}
        dev = if is_pending?(dev), do: set_idle(dev), else: dev
        DevicePool.update(address, dev)
        {:reply, :ok, state}

      _ ->
        {:reply, {:error, :device_not_found}, state}
    end
  end

  def handle_call({:allocating, dapp_address}, _from, %{address: address} = state) do
    with {_pid, dev} <- DevicePool.get(address),
         {:ok, dev} <- set_allocating(dev, dapp_address),
         true <- DevicePool.update(address, dev) do
      {:reply, :ok, state}
    else
      _ ->
        {:reply, {:error, :device_not_found}, state}
    end
  end

  def handle_cast({:release, address, dapp_address}, state) do
    with {_pid, dev} <- DevicePool.get(address),
         ^dapp_address <- dev.dapp_address,
         :ok = DeviceProtocol.alloc_end(address, dapp_address) do
      dev = set_idle(dev)
      DevicePool.update(address, dev)

      {:noreply, state}
    else
      _ ->
        {:noreply, state}
    end
  end

  def is_pending?(device) do
    device.state == @pending
  end

  def is_idle?(device) do
    device.state == @idle
  end

  def set_pending(device) do
    %{device | state: @pending}
  end

  def set_idle(device) do
    %{device | state: @idle, dapp_address: nil}
  end

  def set_allocating(device, dapp_address) do
    if device.state == @idle do
      {:ok, %{device | state: @allocating, dapp_address: dapp_address}}
    else
      {:error, :invalid_state}
    end
  end

  def blank?(value) when is_binary(value) do
    byte_size(value) == 0
  end

  def blank?(value) when is_integer(value) do
    value == 0
  end

  def blank?(nil), do: true
end
