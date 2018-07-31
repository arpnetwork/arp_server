defmodule ARP.Account do
  @moduledoc """
  Manage server account
  """

  alias ARP.Crypto

  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: Account)
  end

  def init_key(auth) do
    GenServer.call(Account, {:init_key, auth}, 10_000)
  end

  def get_info do
    GenServer.call(Account, :get_info)
  end

  # Callbacks

  def init(_opts) do
    {:ok, %{private_key: nil}}
  end

  def handle_call({:init_key, auth}, _from, state) do
    file_name = File.ls!() |> Enum.find(fn x -> String.slice(x, 0, 4) == "UTC-" end)

    with {:ok, file} <- File.read(file_name),
         {:ok, file_map} <- file |> String.downcase() |> Poison.decode(keys: :atoms),
         {:ok, private_key} <- Crypto.decrypt_keystore(file_map, auth) do
      {:reply, :ok, %{state | private_key: private_key}}
    else
      _ ->
        {:reply, :error, state}
    end
  end

  def handle_call(:get_info, _from, state) do
    {:reply, {:ok, state}, state}
  end
end
