defmodule ARP.Device do
  @moduledoc """
  Record online device.
  """

  require Logger

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
    :dapp_price,
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

  def set_allocating(device, dapp_address, dapp_price) do
    if device.state == @idle do
      {:ok, %{device | state: @allocating, dapp_address: dapp_address, dapp_price: dapp_price}}
    else
      {:error, :invalid_state}
    end
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

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
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

  def allocating(pid, dapp_address, dapp_price) do
    if Process.alive?(pid) do
      GenServer.call(pid, {:allocating, dapp_address, dapp_price})
    else
      {:error, :invalid_pid}
    end
  end

  def check_allowance(pid, amount) do
    if pid && Process.alive?(pid) do
      GenServer.call(pid, {:check_allowance, amount})
    else
      {:error, :invalid_pid}
    end
  end

  ## Callbacks

  def init(opts) do
    dev = opts[:device]
    server_addr = Account.address()

    with {:ok, allowance} <- Contract.bank_allowance(server_addr, dev.address),
         true <- allowance.id > 0,
         true <- allowance.expired == 0 do
      Process.send_after(self(), :check, @check_interval)

      {:ok, %{address: dev.address, allowance: allowance, increasing: false}}
    else
      _ ->
        {:stop, :normal}
    end
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

  def handle_call({:allocating, dapp_address, dapp_price}, _from, %{address: address} = state) do
    with {_pid, dev} <- DevicePool.get(address),
         {:ok, dev} <- set_allocating(dev, dapp_address, dapp_price),
         true <- DevicePool.update(address, dev) do
      {:reply, :ok, state}
    else
      _ ->
        {:reply, {:error, :device_not_found}, state}
    end
  end

  def handle_call(
        {:check_allowance, amount},
        _from,
        %{address: address, allowance: allowance, increasing: increasing} = state
      ) do
    approval_amount = Config.get(:device_deposit)

    cond do
      allowance.amount < amount ->
        {:reply, :error, state}

      !increasing && allowance.amount - amount < approval_amount ->
        increase_approval(address, approval_amount, allowance.expired)
        Logger.info("device allowance less than 100 ARP, increasing. address: #{address}")
        {:reply, :ok, %{state | increasing: true}}

      true ->
        {:reply, :ok, state}
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

  def handle_info(:check, %{address: address} = state) do
    server_addr = Account.address()

    with {:ok, %{id: id}} <- Contract.bank_allowance(server_addr, address),
         promise <- DevicePromise.get(address),
         true <- id == 0 || (!is_nil(promise) && promise.cid != id) do
      DevicePromise.delete(address)
      Logger.info("device unbound. address: #{address}")
      {:stop, :normal, state}
    else
      _ ->
        Process.send_after(self(), :check, @check_interval)
        {:noreply, state}
    end
  end

  def handle_info({_ref, :increase_result, allowance}, state) do
    {:noreply, %{state | allowance: allowance, increasing: false}}
  end

  def handle_info(_, state) do
    {:noreply, state}
  end

  defp increase_approval(address, amount, expired) do
    Task.async(fn ->
      server_addr = Account.address()
      private_key = Account.private_key()

      with {:ok, %{"status" => "0x1"}} <-
             Contract.bank_increase_approval(private_key, address, amount, expired) do
        Logger.info("increase allowance success. address: #{address}")
      end

      new_allowance = Contract.bank_allowance(server_addr, address)

      {:increase_result, new_allowance}
    end)
  end
end
