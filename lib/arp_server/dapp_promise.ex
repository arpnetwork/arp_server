defmodule ARP.DappPromise do
  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(dapp_addr) do
    GenServer.call(__MODULE__, {:get, dapp_addr})
  end

  def get_all() do
    GenServer.call(__MODULE__, :get_all)
  end

  def set(dapp_addr, value) do
    GenServer.call(__MODULE__, {:set, dapp_addr, value})
  end

  # Callbacks

  def init(_opts) do
    {:ok, init_promise()}
  end

  def handle_call({:get, dapp_addr}, _from, state) do
    value = Map.get(state, dapp_addr)
    {:reply, value, state}
  end

  def handle_call(:get_all, _from, state) do
    {:reply, state, state}
  end

  def handle_call({:set, dapp_addr, value}, _from, state) do
    save_promise_to_file(dapp_addr, value)
    {:reply, :ok, Map.put(state, dapp_addr, value)}
  end

  defp save_promise_to_file(key, value) do
    file_path = System.user_home() |> Path.join("/.arp_server/dapp_promise")
    file_data = read_promise_file(file_path)

    encode_data = Map.put(file_data, key, value) |> Poison.encode!()
    File.write(file_path, encode_data)
  end

  defp init_promise() do
    file_path = System.user_home() |> Path.join("/.arp_server/dapp_promise")
    read_promise_file(file_path)
  end

  defp read_promise_file(file_path) do
    case File.read(file_path) do
      {:ok, data} ->
        if data == "" do
          %{}
        else
          Poison.decode!(data)
        end

      {:error, _} ->
        %{}
    end
  end
end
