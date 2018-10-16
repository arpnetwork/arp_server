defmodule ARP.DappPool do
  @moduledoc false

  alias ARP.{Account, Contract, Dapp, Nonce, Utils}
  alias ARP.API.JSONRPC2.Protocol
  alias JSONRPC2.Client.HTTP

  require Logger

  use GenServer

  @check_interval 600_000

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(dapp_addr) do
    case :ets.lookup(__MODULE__, dapp_addr) do
      [{_, pid, ip, port}] ->
        {pid, ip, port}

      [] ->
        nil
    end
  end

  def get_all do
    :ets.tab2list(__MODULE__)
  end

  def notify_device_offline(dapp_addr, device_addr) do
    with {_, ip, port} <- get(dapp_addr) do
      method = "device_offline"
      sign_data = [device_addr]

      send_request(dapp_addr, ip, port, method, sign_data)
    end
  end

  def load_bound_dapp do
    GenServer.cast(__MODULE__, :load_bound_dapp)
  end

  def check(dapp_addr) do
    case get(dapp_addr) do
      nil ->
        init_state = Dapp.first_check(dapp_addr)

        case create(dapp_addr, init_state) do
          {:ok, pid} ->
            Dapp.normal?(pid)

          _ ->
            false
        end

      {pid, _, _} ->
        Dapp.normal?(pid)
    end
  end

  def create(dapp_addr, init_state) do
    GenServer.call(__MODULE__, {:create, dapp_addr, init_state})
  end

  def update(dapp_addr, ip, port) do
    GenServer.call(__MODULE__, {:update, dapp_addr, ip, port})
  end

  # Callbacks

  def init(_opts) do
    :ets.new(__MODULE__, [:named_table, read_concurrency: true])

    Process.send_after(self(), :check, @check_interval)

    {:ok, %{refs: %{}}}
  end

  def handle_cast(:load_bound_dapp, state) do
    with {:ok, dapp_list} <- Contract.get_bound_dapp(Account.address()) do
      Task.start(fn ->
        Enum.map(dapp_list, fn dapp_addr -> create(dapp_addr, nil) end)
      end)
    end

    {:noreply, state}
  end

  def handle_call({:create, address, init_state}, _from, %{refs: refs} = state) do
    case get(address) do
      nil ->
        case create_inner(address, init_state) do
          {:ok, pid, ref} ->
            refs = Map.put(refs, ref, address)
            :ets.insert(__MODULE__, {address, pid, nil, nil})
            {:reply, {:ok, pid}, Map.put(state, :refs, refs)}

          err ->
            {:reply, err, state}
        end

      {pid, _, _} ->
        {:reply, {:ok, pid}, state}
    end
  end

  def handle_call({:update, dapp_addr, ip, port}, _from, state) do
    case get(dapp_addr) do
      {pid, old_ip, _} ->
        if is_nil(old_ip) || old_ip != ip do
          :ets.insert(__MODULE__, {dapp_addr, pid, ip, port})
        end

        {:reply, :ok, state}

      nil ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_info(:check, state) do
    dapps = :ets.tab2list(__MODULE__)

    Enum.each(dapps, fn {_, pid, _, _} ->
      Process.send(pid, :check, [])
    end)

    Process.send_after(self(), :check, @check_interval)
    {:noreply, state}
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{refs: refs} = state) do
    {address, refs} = Map.pop(refs, ref)

    if address && :normal != reason do
      # restart
      case create_inner(address, nil) do
        {:ok, pid, ref} ->
          refs = Map.put(refs, ref, address)
          :ets.insert(__MODULE__, {address, pid, nil, nil})
          {:noreply, Map.put(state, :refs, refs)}

        _ ->
          {:noreply, Map.put(state, :refs, refs)}
      end
    else
      {:noreply, Map.put(state, :refs, refs)}
    end
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  defp create_inner(address, init_state) do
    case DynamicSupervisor.start_child(
           ARP.DynamicSupervisor,
           {ARP.Dapp, [address: address, init_state: init_state]}
         ) do
      {:ok, pid} ->
        ref = Process.monitor(pid)
        {:ok, pid, ref}

      err ->
        err
    end
  end

  defp send_request(dapp_address, ip, port, method, data) do
    private_key = Account.private_key()
    address = Account.address()

    nonce = address |> Nonce.get_and_update_nonce(dapp_address) |> Utils.encode_integer()
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
