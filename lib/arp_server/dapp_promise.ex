defmodule ARP.DappPromise do
  use GenServer

  @file_path Application.get_env(:arp_server, :data_dir)
             |> Path.join("dapp_promise")
             |> String.to_charlist()

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(dapp_addr) do
    case :ets.lookup(__MODULE__, dapp_addr) do
      [{^dapp_addr, value}] ->
        value

      [] ->
        nil
    end
  end

  def get_all() do
    :ets.match_object(__MODULE__, {:"$1", :"$2"})
  end

  def set(dapp_addr, value) do
    GenServer.call(__MODULE__, {:set, dapp_addr, value})
  end

  def delete(dapp_addr) do
    GenServer.call(__MODULE__, {:delete, dapp_addr})
  end

  # Callbacks

  def init(_opts) do
    tab =
      case :ets.file2tab(@file_path, verify: true) do
        {:ok, tab} ->
          tab

        _ ->
          :ets.new(__MODULE__, [:named_table, read_concurrency: true])
      end

    {:ok, tab}
  end

  def handle_call({:set, dapp_addr, value}, _from, tab) do
    :ets.insert(tab, {dapp_addr, value})
    write_file(tab)
    {:reply, :ok, tab}
  end

  def handle_call({:delete, dapp_addr}, _from, tab) do
    :ets.delete(tab, dapp_addr)
    write_file(tab)
    {:reply, :ok, tab}
  end

  def write_file(tab) do
    :ets.tab2file(tab, @file_path, extended_info: [:md5sum])
  end
end
