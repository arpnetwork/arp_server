defmodule ARP.Nonce do
  @moduledoc """
  Manager send nonce.
  """
  @nonce_path Application.get_env(:arp_server, :data_dir)
              |> Path.join("nonce")
              |> String.to_charlist()

  def init do
    case :ets.file2tab(@nonce_path, verify: true) do
      {:ok, tab} ->
        tab

      _ ->
        :ets.new(__MODULE__, [:named_table, :public, read_concurrency: true])
    end
  end

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
    :ets.tab2file(__MODULE__, @nonce_path, extended_info: [:md5sum])
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
      :ets.tab2file(__MODULE__, @nonce_path, extended_info: [:md5sum])
      :ok
    else
      {:error, :nonce_too_low}
    end
  end
end
