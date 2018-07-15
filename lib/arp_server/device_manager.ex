defmodule ARP.DeviceManager do
  @moduledoc """
  To manage online devices
  """

  alias ARP.Device

  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def online(%{id: id} = device) when is_binary(id) and byte_size(id) > 0 do
    GenServer.call(__MODULE__, {:online, device})
  end

  def offline(id) do
    GenServer.call(__MODULE__, {:offline, id})
  end

  def selection do
    GenServer.call(__MODULE__, :selection)
  end

  def request(filters, user_id) when is_map(filters) and is_binary(user_id) do
    GenServer.call(__MODULE__, {:request, filters, user_id})
  end

  def use(id) do
    GenServer.call(__MODULE__, {:use, id})
  end

  def idle(id) do
    GenServer.call(__MODULE__, {:idle, id})
  end

  def clear do
    GenServer.call(__MODULE__, :clear)
  end

  def get(id) do
    GenServer.call(__MODULE__, {:get, id})
  end

  ## Callbacks

  def init(_opts) do
    {:ok, %{}}
  end

  def handle_call({:online, device}, _from, devices) do
    unless Map.has_key?(devices, device.id) do
      device = Device.set_idle(device)
      {:reply, {:ok, device}, Map.put(devices, device.id, device)}
    else
      {:reply, {:error, :invalid_param}, devices}
    end
  end

  def handle_call({:offline, id}, _from, devices) do
    if Map.has_key?(devices, id) do
      {:reply, :ok, Map.delete(devices, id)}
    else
      {:reply, {:error, :not_found}, devices}
    end
  end

  def handle_call(:selection, _from, devices) do
    {:reply, devices |> Map.values() |> Device.select_fields(), devices}
  end

  def handle_call({:request, filters, user_id}, _from, devices) do
    with {_, dev} <-
           Enum.find(devices, :error, fn {_, device} ->
             Device.is_idle?(device) and Device.match(device, filters)
           end),
         {:ok, dev} <- Device.set_requesting(dev, user_id) do
      {:reply, {:ok, dev}, Map.put(devices, dev.id, dev)}
    else
      _ ->
        {:reply, {:error, :no_free_device}, devices}
    end
  end

  def handle_call({:use, id}, _from, devices) do
    with {:ok, device} <- Map.fetch(devices, id),
         {:ok, dev} <- Device.set_using(device) do
      {:reply, {:ok, dev}, Map.put(devices, dev.id, dev)}
    else
      {:error, _} ->
        {:reply, {:error, :invalid_param}, devices}

      :error ->
        {:reply, {:error, :not_found}, devices}
    end
  end

  def handle_call({:idle, id}, _from, devices) do
    case Map.fetch(devices, id) do
      {:ok, dev} ->
        dev = Device.set_idle(dev)
        {:reply, {:ok, dev}, Map.put(devices, dev.id, dev)}

      :error ->
        {:reply, {:error, :not_found}, devices}
    end
  end

  def handle_call(:clear, _from, _devices) do
    {:reply, :ok, %{}}
  end

  def handle_call({:get, id}, _from, devices) do
    {:reply, Map.get(devices, id), devices}
  end
end
