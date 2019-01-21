defmodule ARP.DappManager.Pool do
  @moduledoc """
  Pool
  """

  alias ARP.DappManager.Dapp

  require Logger

  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(dapp_addr) do
    case :ets.lookup(__MODULE__, dapp_addr) do
      [{_, pid}] -> pid
      [] -> nil
    end
  end

  def get_all do
    :ets.tab2list(__MODULE__)
  end

  def create(dapp_addr, ip, port) do
    GenServer.call(__MODULE__, {:create, dapp_addr, ip, port})
  end

  # Callbacks

  def init(_opts) do
    :ets.new(__MODULE__, [:named_table, read_concurrency: true])

    {:ok, %{refs: %{}}}
  end

  def handle_call({:create, address, ip, port}, _from, %{refs: refs} = state) do
    case get(address) do
      nil ->
        case create_inner(address, ip, port) do
          {:ok, pid, ref} ->
            :ets.insert(__MODULE__, {address, pid})
            refs = Map.put(refs, ref, address)
            {:reply, {:ok, pid}, Map.put(state, :refs, refs)}

          err ->
            {:reply, err, state}
        end

      pid ->
        {:reply, {:ok, pid}, state}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{refs: refs} = state) do
    {address, refs} = Map.pop(refs, ref)

    with true <- address && whether_restart(reason),
         {:ok, pid, ref} <- create_inner(address, nil, nil) do
      :ets.insert(__MODULE__, {address, pid})
      refs = Map.put(refs, ref, address)
      {:noreply, Map.put(state, :refs, refs)}
    else
      _ ->
        :ets.delete(__MODULE__, address)
        {:noreply, Map.put(state, :refs, refs)}
    end
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  defp whether_restart(:normal) do
    false
  end

  defp whether_restart(:shutdown) do
    false
  end

  defp whether_restart({:shutdown, _}) do
    false
  end

  defp whether_restart(_) do
    true
  end

  defp create_inner(address, ip, port) do
    case DynamicSupervisor.start_child(:dapp_pool, {Dapp, [address: address, ip: ip, port: port]}) do
      {:ok, pid} ->
        ref = Process.monitor(pid)
        {:ok, pid, ref}

      err ->
        err
    end
  end
end
