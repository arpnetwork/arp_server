defmodule ARP.Nonce do
  @moduledoc """
  Manager send nonce.
  """

  alias ARP.Config

  use GenServer

  def get(from, to) do
    case :ets.lookup(__MODULE__, {from, to}) do
      [{_, value}] ->
        value

      [] ->
        0
    end
  end

  def get_all do
    :ets.tab2list(__MODULE__)
  end

  def get_and_update_nonce(from, to) do
    nonce = :ets.update_counter(__MODULE__, {from, to}, 1, {{from, to}, 0})
    GenServer.cast(__MODULE__, :write)
    nonce
  end

  def check_and_update_nonce(from, to, nonce) do
    tuple = {from, to}

    unless :ets.member(__MODULE__, tuple) do
      :ets.insert_new(__MODULE__, {tuple, 0})
    end

    ms = [
      {{:"$1", :"$2"},
       [
         {:andalso, {:==, :"$1", {:const, tuple}}, {:<, :"$2", {:const, nonce}}}
       ], [{{:"$1", {:const, nonce}}}]}
    ]

    if 1 == :ets.select_replace(__MODULE__, ms) do
      GenServer.cast(__MODULE__, :write)
      :ok
    else
      {:error, :nonce_too_low}
    end
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
          :ets.new(__MODULE__, [:named_table, :public, read_concurrency: true])
      end

    {:ok, %{tab: tab}}
  end

  def handle_cast(:write, %{tab: tab} = state) do
    :ets.tab2file(tab, file_path(), extended_info: [:md5sum])
    {:noreply, state}
  end

  defp file_path do
    Config.get(:data_path)
    |> Path.join("nonce")
    |> String.to_charlist()
  end
end
