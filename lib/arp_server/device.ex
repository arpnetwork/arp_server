defmodule ARP.Device do
  @moduledoc """
  Record online device.
  """

  alias ARP.DeviceNetSpeed

  use GenServer

  # state value
  @pending 0
  @idle 1
  @allocating 2

  defstruct [
    :address,
    :ip,
    :port,
    :state,
    :dapp_address,
    :brand,
    :model,
    :cpu,
    :gpu,
    :ram,
    :storage,
    :os_ver,
    :system_ver,
    :resolution,
    :imsi,
    :telecom_operator,
    :connectivity,
    :telephony,
    :upload_speed,
    :download_speed,
    :ver
  ]

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def online(%{address: address} = device) when is_binary(address) and byte_size(address) > 0 do
    GenServer.call(__MODULE__, {:online, device})
  end

  def offline(address) do
    GenServer.call(__MODULE__, {:offline, address})
  end

  def selection do
    GenServer.call(__MODULE__, :selection)
  end

  def request(filters, dapp_address) when is_map(filters) and is_binary(dapp_address) do
    GenServer.call(__MODULE__, {:request, filters, dapp_address})
  end

  def idle(address) do
    GenServer.call(__MODULE__, {:idle, address})
  end

  def clear do
    GenServer.call(__MODULE__, :clear)
  end

  def get(address) do
    GenServer.call(__MODULE__, {:get, address})
  end

  def update_net_speed(ids, upload_speed, download_speed)
      when is_list(ids) and is_integer(upload_speed) and is_integer(download_speed) do
    GenServer.cast(__MODULE__, {:update_net_speed, ids, upload_speed, download_speed})
  end

  ## Callbacks

  def init(_opts) do
    {:ok, %{}}
  end

  def handle_call({:online, device}, _from, devices) do
    unless Map.has_key?(devices, device.address) do
      DeviceNetSpeed.online(device.ip, device.address)

      device = set_pending(device)
      {:reply, {:ok, device}, Map.put(devices, device.address, device)}
    else
      {:reply, {:error, :invalid_param}, devices}
    end
  end

  def handle_call({:offline, address}, _from, devices) do
    if Map.has_key?(devices, address) do
      {dev, devices} = Map.pop(devices, address)

      if dev do
        DeviceNetSpeed.offline(dev.ip, address)
      end

      {:reply, :ok, devices}
    else
      {:reply, {:error, :not_found}, devices}
    end
  end

  def handle_call(:selection, _from, devices) do
    {:reply, devices |> Map.values() |> select_fields(), devices}
  end

  def handle_call({:request, filters, dapp_address}, _from, devices) do
    with {_, dev} <-
           Enum.find(devices, :error, fn {_, device} ->
             is_idle?(device) and match(device, filters)
           end),
         {:ok, dev} <- set_allocating(dev, dapp_address) do
      {:reply, {:ok, dev}, Map.put(devices, dev.address, dev)}
    else
      _ ->
        {:reply, {:error, :no_free_device}, devices}
    end
  end

  def handle_call({:idle, address}, _from, devices) do
    case Map.fetch(devices, address) do
      {:ok, dev} ->
        dev = set_idle(dev)
        {:reply, {:ok, dev}, Map.put(devices, dev.address, dev)}

      :error ->
        {:reply, {:error, :not_found}, devices}
    end
  end

  def handle_call(:clear, _from, _devices) do
    {:reply, :ok, %{}}
  end

  def handle_call({:get, address}, _from, devices) do
    {:reply, Map.get(devices, address), devices}
  end

  def handle_cast({:update_net_speed, ids, upload_speed, download_speed}, devices) do
    devices =
      Enum.reduce(ids, devices, fn id, acc ->
        if Map.has_key?(acc, id) do
          dev = %{acc[id] | upload_speed: upload_speed, download_speed: download_speed}
          dev = if is_pending?(dev), do: set_idle(dev), else: dev

          Map.put(acc, id, dev)
        else
          acc
        end
      end)

    {:noreply, devices}
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

  @doc """
  Detect whether the device matches the filters
  """
  def match(device, filters) do
    res =
      Enum.reject(filters, fn {key, value} ->
        if blank?(value) do
          true
        else
          case key do
            :cpu -> device.cpu == value
            :gpu -> device.gpu == value
            :ram -> device.ram >= value
            :upload_speed -> device.upload_speed >= value
            :download_speed -> device.download_speed >= value
            _ -> true
          end
        end
      end)

    Enum.empty?(res)
  end

  @doc """
  Return field map with value list for user selection.
  Only free device can be selected.
  """
  def select_fields(devices) when is_list(devices) do
    fields = [:cpu, :ram, :gpu, :upload_speed, :download_speed]

    res =
      List.foldl(devices, %{}, fn device, acc ->
        if is_idle?(device) do
          for field <- fields, v = Map.get(device, field), !blank?(v), into: %{} do
            {field, [v | acc[field] || []]}
          end
        else
          acc
        end
      end)

    for {k, v} <- res, into: %{} do
      {k, v |> Enum.uniq()}
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
