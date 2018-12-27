defmodule ARP.DappPromise do
  @moduledoc false

  alias ARP.Config

  use GenServer

  def set(dapp_addr, promise) do
    :ets.insert(__MODULE__, {dapp_addr, promise})
    GenServer.cast(__MODULE__, :write)
  end

  def get(dapp_addr) do
    case :ets.lookup(__MODULE__, dapp_addr) do
      [{^dapp_addr, value}] ->
        value

      [] ->
        nil
    end
  end

  def get_all do
    :ets.tab2list(__MODULE__)
  end

  def delete(dapp_addr) do
    :ets.delete(__MODULE__, dapp_addr)
    GenServer.cast(__MODULE__, :write)
  end

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  # Callbacks

  def init(_opts) do
    tab =
      case :ets.file2tab(file_path(), verify: true) do
        {:ok, tab} ->
          tab

        _ ->
          :ets.new(__MODULE__, [
            :named_table,
            :public,
            write_concurrency: true,
            read_concurrency: true
          ])
      end

    {:ok, %{tab: tab}}
  end

  def handle_cast(:write, %{tab: tab} = state) do
    :ets.tab2file(tab, file_path(), extended_info: [:md5sum])
    {:noreply, state}
  end

  defp file_path do
    Config.get(:data_path)
    |> Path.join("dapp_promise")
    |> String.to_charlist()
  end
end
