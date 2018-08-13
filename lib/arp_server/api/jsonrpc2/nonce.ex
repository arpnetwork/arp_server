defmodule ARP.API.JSONRPC2.Nonce do
  @moduledoc """
  Manager nonce.
  """

  use GenServer

  @spec check_and_update_nonce(String.t(), integer()) :: :ok | {:error, atom()}
  def check_and_update_nonce(address, nonce) do
    GenServer.call(__MODULE__, {:check_and_update_nonce, address, nonce})
  end

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  # Callbacks

  def init(_opts) do
    {:ok, %{}}
  end

  def handle_call({:check_and_update_nonce, address, nonce}, _from, state) do
    if Map.get(state, address, 0) < nonce do
      {:reply, :ok, Map.put(state, address, nonce)}
    else
      {:reply, {:error, :nonce_too_low}, state}
    end
  end
end
