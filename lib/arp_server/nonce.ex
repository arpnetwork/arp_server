defmodule ARP.Nonce do
  @moduledoc """
  Manager send nonce.
  """

  use GenServer

  def get_and_update_nonce(address) do
    GenServer.call(__MODULE__, {:get_and_update_nonce, address})
  end

  def get_all() do
    GenServer.call(__MODULE__, :get_all)
  end

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  # Callbacks

  def init(_opts) do
    {:ok, init_nonce()}
  end

  def handle_call({:get_and_update_nonce, address}, _from, state) do
    nonce = Map.get(state, address, 0)
    nonce = nonce + 1
    save_nonce_to_file(address, nonce)
    {:reply, nonce, Map.put(state, address, nonce)}
  end

  def handle_call(:get_all, _from, state) do
    {:reply, state, state}
  end

  defp save_nonce_to_file(address, nonce) do
    file_path = System.user_home() |> Path.join("/.arp_server/nonce")
    file_data = read_nonce_file(file_path)

    encode_data = Map.put(file_data, address, nonce) |> Poison.encode!()
    File.write(file_path, encode_data)
  end

  defp init_nonce() do
    file_path = System.user_home() |> Path.join("/.arp_server/nonce")
    read_nonce_file(file_path)
  end

  defp read_nonce_file(file_path) do
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
