defmodule ARP.DevicePool do
  @moduledoc false

  alias ARP.{Account, DappPool, Device, DeviceNetSpeed, Nonce, Utils}
  alias ARP.API.JSONRPC2.Protocol
  alias ARP.API.TCP.DeviceProtocol
  alias JSONRPC2.Client.HTTP

  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(address) do
    case :ets.lookup(__MODULE__, address) do
      [{^address, pid, dev}] -> {pid, dev}
      [] -> nil
    end
  end

  def get_all do
    :ets.tab2list(__MODULE__)
  end

  def size do
    :ets.info(__MODULE__, :size)
  end

  def update(address, device) do
    case get(address) do
      {pid, _dev} ->
        :ets.insert(__MODULE__, {address, pid, device})

      _ ->
        :error
    end
  end

  def delete(address) do
    :ets.delete(__MODULE__, address)
  end

  def online(device) do
    GenServer.call(__MODULE__, {:online, device})
  end

  def offline(address) do
    case get(address) do
      {pid, dev} ->
        Device.offline(pid, dev)

        if Device.is_allocating?(dev) && !is_nil(dev.dapp_address) do
          device_offline(address, dev.dapp_address)
        end

        :ok

      _ ->
        {:error, :invalid_param}
    end
  end

  def idle(address) do
    case get(address) do
      {pid, dev} ->
        Device.idle(pid)

        if Device.is_allocating?(dev) && !is_nil(dev.dapp_address) do
          device_offline(address, dev.dapp_address)
        end

        :ok

      _ ->
        {:error, :device_not_found}
    end
  end

  def update_net_speed(addr_list, upload_speed, download_speed)
      when is_list(addr_list) and is_integer(upload_speed) and is_integer(download_speed) do
    Enum.each(addr_list, fn address ->
      case get(address) do
        {pid, _dev} ->
          Device.update_net_speed(pid, upload_speed, download_speed)

        _ ->
          nil
      end
    end)
  end

  def request(dapp_address, price, ip, port) do
    if DappPool.check(dapp_address) do
      GenServer.call(__MODULE__, {:request, dapp_address, price, ip, port})
    else
      {:error, :bind_error}
    end
  end

  def release(address, dapp_address) do
    case get(address) do
      {pid, _dev} ->
        Device.release(pid, address, dapp_address)

      _ ->
        {:error, :device_not_found}
    end
  end

  def release_by_dapp(dapp_address) do
    # :ets.fun2ms(fn {addr, pid, dev} when :erlang.map_get(:dapp_address, dev) == dapp_address  -> {addr, pid, dev} end)
    match = [
      {{:"$1", :"$2", :"$3"}, [{:==, {:map_get, :dapp_address, :"$3"}, {:const, dapp_address}}],
       [{{:"$1", :"$2", :"$3"}}]}
    ]

    list = :ets.select(__MODULE__, match)

    Enum.each(list, fn {address, pid, _dev} ->
      Device.release(pid, address, dapp_address)
    end)
  end

  # Callbacks

  def init(_opts) do
    :ets.new(__MODULE__, [:named_table, :public, write_concurrency: true, read_concurrency: true])
    {:ok, %{refs: %{}}}
  end

  def handle_call({:online, device}, _from, %{refs: refs} = state) do
    addr = device.address

    case get(addr) do
      nil ->
        case create(device) do
          {:ok, ref} ->
            if Device.is_pending?(device) do
              DeviceNetSpeed.online(device.ip, device.address)
            end

            refs = Map.put(refs, ref, addr)
            {:reply, :ok, Map.put(state, :refs, refs)}

          {:error, err} ->
            {:reply, {:error, err}, state}
        end

      _ ->
        {:reply, {:error, :invalid_param}, state}
    end
  end

  def handle_call({:request, dapp_address, price, ip, port}, _from, state) do
    with {:ok, dev} <- find_device(%{price: price}),
         {pid, _dev} <- get(dev.address),
         :ok <- Device.allocating(pid, dapp_address),
         :ok <- DappPool.update(dapp_address, ip, port),
         # prepare device
         :ok <- DeviceProtocol.user_request(dev.address, dapp_address, ip, port, price) do
      dev_info = %{
        address: dev.address,
        ip: dev.ip,
        port: dev.port,
        width: dev.width,
        height: dev.height
      }

      {:reply, dev_info, state}
    else
      %{amount: _} ->
        {:reply, {:error, :no_enough_locked_arp}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}

      _ ->
        {:reply, :error, state}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{refs: refs} = state) do
    {address, refs} = Map.pop(refs, ref)

    if address && :normal != reason do
      # restart
      with {_pid, dev} <- get(address),
           {:ok, ref} <- create(dev) do
        refs = Map.put(refs, ref, address)
        {:noreply, Map.put(state, :refs, refs)}
      else
        _ ->
          {:noreply, Map.put(state, :refs, refs)}
      end
    else
      {:noreply, Map.put(state, :refs, refs)}
    end
  end

  defp create(dev) do
    case DynamicSupervisor.start_child(ARP.DynamicSupervisor, {ARP.Device, [device: dev]}) do
      {:ok, pid} ->
        :ets.insert(__MODULE__, {dev.address, pid, dev})
        ref = Process.monitor(pid)
        {:ok, ref}

      _ ->
        {:error, :online_faild}
    end
  end

  defp find_device(filters) do
    # :ets.fun2ms(fn {addr, pid, dev} when :erlang.map_get(:state, dev) == 1 -> dev end)
    match = [{{:"$1", :"$2", :"$3"}, [{:==, {:map_get, :state, :"$3"}, 1}], [:"$3"]}]

    with devices <- :ets.select(__MODULE__, match),
         dev when not is_nil(dev) <-
           Enum.find(devices, nil, fn device -> match(device, filters) end) do
      {:ok, dev}
    else
      _ ->
        {:error, :no_free_device}
    end
  end

  # Detect whether the device matches the filters
  defp match(device, filters) do
    res =
      Enum.reject(filters, fn {key, value} ->
        if Device.blank?(value) do
          true
        else
          case key do
            :cpu -> device.cpu == value
            :gpu -> device.gpu == value
            :ram -> device.ram >= value
            :upload_speed -> device.upload_speed >= value
            :download_speed -> device.download_speed >= value
            :price -> device.price <= value
            _ -> true
          end
        end
      end)

    Enum.empty?(res)
  end

  defp device_offline(device_address, dapp_address) do
    method = "device_offline"
    sign_data = [device_address]

    {_, ip, port} = DappPool.get_item(dapp_address)

    case send_request(dapp_address, ip, port, method, sign_data) do
      {:ok, _result} ->
        :ok

      {:error, error} ->
        {:error, error}
    end
  end

  defp send_request(dapp_address, ip, port, method, data) do
    private_key = Account.private_key()
    address = Account.address()

    nonce = Nonce.get_and_update_nonce(address, dapp_address) |> Utils.encode_integer()
    url = "http://#{ip}:#{port}"

    sign = Protocol.sign(method, data, nonce, dapp_address, private_key)

    case HTTP.call(url, method, data ++ [nonce, sign]) do
      {:ok, result} ->
        if Protocol.verify_resp_sign(result, address, dapp_address) do
          {:ok, result}
        else
          {:error, :verify_error}
        end

      {:error, err} ->
        {:error, err}
    end
  end
end
