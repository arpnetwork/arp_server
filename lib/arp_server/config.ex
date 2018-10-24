defmodule ARP.Config do
  @moduledoc false

  alias ARP.Utils

  use GenServer

  @config_path Application.get_env(:arp_server, :data_dir)
               |> Path.join("config")
               |> String.to_charlist()

  @external_config [
    {:port, :integer},
    {:deposit, :integer},
    {:max_load, :integer},
    {:ip, :binary},
    {:bandwidth, :integer},
    {:keystore, :map}
  ]

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def init(_opts) do
    tab =
      case :ets.file2tab(@config_path, verify: true) do
        {:ok, tab} ->
          tab

        _ ->
          :ets.new(__MODULE__, [:named_table, read_concurrency: true])
      end

    fixed_config = Application.get_all_env(:arp_server)
    :ets.insert(tab, fixed_config)

    write_file(tab)

    {:ok, tab}
  end

  def set(key, value) do
    if List.keymember?(@external_config, key, 0) && check_data_type(value, @external_config[key]) do
      GenServer.cast(__MODULE__, {:set, key, value})
    else
      {:error, :invalid_params}
    end
  end

  def set(configs) do
    if Enum.all?(configs, fn {key, value} ->
         List.keymember?(@external_config, key, 0) &&
           check_data_type(value, @external_config[key])
       end) do
      GenServer.cast(__MODULE__, {:set, configs})
    else
      {:error, :invalid_params}
    end
  end

  def get(key) do
    case :ets.lookup(__MODULE__, key) do
      [{^key, value}] -> value
      [] -> nil
    end
  end

  def all do
    :ets.tab2list(__MODULE__)
  end

  def external do
    all()
    |> Enum.filter(fn {key, _} -> List.keymember?(@external_config, key, 0) end)
  end

  def check do
    configs = all()
    Enum.all?(@external_config, fn {key, _} -> List.keymember?(configs, key, 0) end)
  end

  def encode(configs) do
    Enum.map(configs, fn {key, value} ->
      v =
        case key do
          :deposit -> Utils.encode_integer(value)
          _ -> value
        end

      {key, v}
    end)
  end

  def decode(configs) do
    Enum.map(configs, fn {key, value} ->
      v =
        case key do
          :deposit -> Utils.decode_hex(value)
          _ -> value
        end

      {key, v}
    end)
  end

  def handle_cast({:set, key, value}, tab) do
    :ets.insert(tab, {key, value})
    write_file(tab)
    {:noreply, tab}
  end

  def handle_cast({:set, configs}, tab) do
    :ets.insert(tab, configs)
    write_file(tab)
    {:noreply, tab}
  end

  defp write_file(tab) do
    :ets.tab2file(tab, @config_path, extended_info: [:md5sum])
  end

  defp check_data_type(data, type) do
    apply(Kernel, String.to_existing_atom("is_#{type}"), [data])
  end
end
