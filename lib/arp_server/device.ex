defmodule ARP.Device do
  @moduledoc """
  Record online device.
  """

  alias ARP.{Account, Config, Contract, DevicePool, DevicePromise}
  alias ARP.API.TCP.DeviceProtocol

  use GenServer, restart: :temporary

  # state value
  @pending 0
  @idle 1
  @allocating 2

  @check_interval 1000 * 60 * 10

  defstruct [
    :address,
    :tcp_pid,
    :price,
    :ip,
    :original_ip,
    :tcp_port,
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
    :net_type,
    :ver,
    :cid,
    state: @pending
  ]

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  def check_port(host, tcp_port) do
    with true <- Enum.member?(0..65_535, tcp_port),
         {:ok, socket} <- :gen_tcp.connect(host, tcp_port, [active: false], 5000),
         {{:ok, data}, _} when data == [0, 0, 0, 0] <- {:gen_tcp.recv(socket, 4, 5000), socket},
         :gen_tcp.close(socket) do
      :ok
    else
      {{_, _}, socket} ->
        :gen_tcp.close(socket)
        :error

      _ ->
        :error
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

    Process.send_after(self(), :check_interval, 30_000)

    {:ok, %{address: dev.address, increasing: false}}
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
         :ok = DeviceProtocol.alloc_end(dev.tcp_pid, dapp_address) do
      dev = set_idle(dev)
      DevicePool.update(address, dev)

      {:noreply, state}
    else
      _ ->
        {:noreply, state}
    end
  end

  def handle_info(:check_interval, %{address: address, increasing: increasing} = state) do
    pid = self()
    Process.send_after(pid, :check_interval, @check_interval)

    server_addr = Account.address()
    private_key = Account.private_key()

    with %{cid: cid, amount: device_amount} <- DevicePromise.get(address),
         {:ok, %{id: allowance_cid, amount: current_amount, expired: expired}} <-
           Contract.bank_allowance(server_addr, address) do
      approval_amount = Config.get(:device_deposit)

      if increasing == false && cid == allowance_cid &&
           device_amount > round(current_amount * 0.8) do
        Task.start(fn ->
          Contract.bank_increase_approval(private_key, address, approval_amount, expired)
          Process.send(pid, :change_increasing, [])
        end)

        {:noreply, %{state | increasing: true}}
      else
        {:noreply, state}
      end
    else
      _ ->
        {:noreply, state}
    end
  end

  def handle_info(:change_increasing, state) do
    {:noreply, %{state | increasing: false}}
  end

  def is_pending?(device) do
    device.state == @pending
  end

  def is_idle?(device) do
    device.state == @idle
  end

  def is_allocating?(device) do
    device.state == @allocating
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
