defmodule ARP.DevicePromise do
  alias ARP.API.JSONRPC2.Protocol
  alias JSONRPC2.Client.HTTP
  alias ARP.Account

  use GenServer

  @file_path Application.get_env(:arp_server, :data_dir)
             |> Path.join("device_promise")
             |> String.to_charlist()

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get(device_addr) do
    case :ets.lookup(__MODULE__, device_addr) do
      [{^device_addr, value}] ->
        value

      [] ->
        nil
    end
  end

  def get_all() do
    :ets.match_object(__MODULE__, {:"$1", :"$2"})
  end

  def set(device_addr, value) do
    GenServer.call(__MODULE__, {:set, device_addr, value})
  end

  def delete(device_addr) do
    GenServer.call(__MODULE__, {:delete, device_addr})
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

  def handle_call({:set, device_addr, value}, _from, tab) do
    :ets.insert(tab, {device_addr, value})
    write_file(tab)
    {:reply, :ok, tab}
  end

  def handle_call({:delete, device_addr}, _from, tab) do
    :ets.delete(tab, device_addr)
    write_file(tab)
    {:reply, :ok, tab}
  end

  def write_file(tab) do
    :ets.tab2file(tab, @file_path, extended_info: [:md5sum])
  end

  def account_pay(device_address, promise) do
    method = "account_pay"
    sign_data = [promise]

    {_pid, %{ip: ip, port: port}} = ARP.DevicePool.get(device_address)

    case send_request(device_address, ip, port + 1, method, sign_data) do
      {:ok, _result} ->
        :ok

      {:error, error} ->
        {:error, error}
    end
  end

  defp send_request(device_address, ip, port, method, data) do
    private_key = Account.private_key()
    address = Account.address()

    nonce = ARP.Nonce.get_and_update_nonce(address, device_address) |> ARP.Utils.encode_integer()
    url = "http://#{ip}:#{port}"

    sign = Protocol.sign(method, data, nonce, device_address, private_key)

    case HTTP.call(url, method, data ++ [nonce, sign]) do
      {:ok, result} ->
        if Protocol.verify_resp_sign(result, address, device_address) do
          {:ok, result}
        else
          {:error, :verify_error}
        end

      {:error, err} ->
        {:error, err}
    end
  end
end
