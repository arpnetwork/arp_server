defmodule ARP.Account.Promise do
  @moduledoc false

  alias ARP.{Config, Crypto, Utils}

  use GenServer

  defstruct [:cid, :from, :to, :amount, :sign, :paid]

  def create(private_key, cid, from, to, amount, paid \\ 0) do
    decoded_from = from |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    decoded_to = to |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    data =
      <<cid::size(256), decoded_from::binary-size(20), decoded_to::binary-size(20),
        amount::size(256)>>

    sign = Crypto.eth_sign(data, private_key)

    %__MODULE__{
      cid: cid,
      from: from,
      to: to,
      amount: amount,
      sign: sign,
      paid: paid
    }
  end

  def verify(%__MODULE__{cid: cid} = p, from, to) do
    cid = if(is_binary(cid), do: Utils.decode_hex(cid), else: cid)
    verify(p, cid, from, to)
  end

  def verify(%__MODULE__{cid: cid} = p, cid, from, to) when is_binary(cid) do
    verify(decode(p), cid, from, to)
  end

  def verify(%__MODULE__{cid: cid} = p, cid, from, to) when is_integer(cid) do
    if p.cid && p.from && p.to && p.amount && p.sign && p.cid == cid && p.from == from &&
         p.to == to do
      from_binary = p.from |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
      to_binary = p.to |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

      encode = <<p.cid::size(256), from_binary::binary, to_binary::binary, p.amount::size(256)>>

      with {:ok, recover_addr} <- Crypto.eth_recover(encode, p.sign) do
        recover_addr == from
      else
        _ -> false
      end
    else
      false
    end
  rescue
    _ ->
      false
  end

  def encode(%__MODULE__{} = promise) do
    %__MODULE__{
      cid: promise.cid |> Utils.encode_integer(),
      from: promise.from,
      to: promise.to,
      amount: promise.amount |> Utils.encode_integer(),
      sign: promise.sign,
      paid: (promise.paid || 0) |> Utils.encode_integer()
    }
  end

  def decode(%__MODULE__{} = promise) do
    %__MODULE__{
      cid: promise.cid |> Utils.decode_hex(),
      from: promise.from,
      to: promise.to,
      amount: promise.amount |> Utils.decode_hex(),
      sign: promise.sign,
      paid: (promise.paid || "0x0") |> Utils.decode_hex()
    }
  end

  @doc """
  {{:device, address}, promise}
  {{:dapp, address}, promise}
  """
  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get_device(address) do
    get(:device, address)
  end

  def get_dapp(address) do
    get(:dapp, address)
  end

  def get(type, address) do
    case :ets.lookup(__MODULE__, {type, address}) do
      [{_, value}] -> value
      [] -> nil
    end
  end

  def get_all_device do
    get_all(:device)
  end

  def get_all_dapp do
    get_all(:dapp)
  end

  def get_all(type) do
    # :ets.fun2ms(fn {{type, address}, promise} when type == t -> {address, promise} end)
    match = [{{{:"$1", :"$2"}, :"$3"}, [{:==, :"$1", {:const, type}}], [{{:"$2", :"$3"}}]}]
    :ets.select(__MODULE__, match)
  end

  def set_device(address, promise) do
    set(:device, address, promise)
  end

  def set_dapp(address, promise) do
    set(:dapp, address, promise)
  end

  def set(type, address, promise) do
    :ets.insert(__MODULE__, {{type, address}, promise})
    GenServer.cast(__MODULE__, :write)
  end

  def delete_device(address) do
    delete(:device, address)
  end

  def delete_dapp(address) do
    delete(:dapp, address)
  end

  def delete(type, address) do
    :ets.delete(__MODULE__, {type, address})
    GenServer.cast(__MODULE__, :write)
  end

  # Callbacks

  def init(_opts) do
    with {:error, _} <- :ets.file2tab(file_path(), verify: true) do
      :ets.new(__MODULE__, [
        :named_table,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

      GenServer.cast(__MODULE__, :write)
    end

    {:ok, %{}}
  end

  def handle_cast(:write, state) do
    :ets.tab2file(__MODULE__, file_path(), extended_info: [:md5sum], sync: true)
    {:noreply, state}
  end

  defp file_path do
    Config.get(:data_path)
    |> Path.join("promise")
    |> String.to_charlist()
  end
end
