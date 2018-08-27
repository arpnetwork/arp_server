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

  def get_all do
    :ets.match_object(__MODULE__, {:"$1", :"$2"})
  end

  def get_and_update_nonce(address) do
    nonce = :ets.update_counter(__MODULE__, address, 1, {address, 0})
    :ets.tab2file(__MODULE__, @nonce_path, extended_info: [:md5sum])
    nonce
  end
end
