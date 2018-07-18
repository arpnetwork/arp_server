defmodule ARP.Device do
  @moduledoc """
  Define a device struct to record online device.
  """

  # state value
  @idle 0
  @requesting 1
  @using 2

  defstruct [
    :id,
    :ip,
    :port,
    :state,
    :user_id,
    :brand,
    :model,
    :cpu_vendor,
    :cpu,
    :gpu,
    :ram,
    :storage,
    :os_ver,
    :system_ver,
    :resolution,
    :imsi,
    :telecom_operator,
    :conn_net_type,
    :tel_net_type,
    :upload_speed,
    :download_speed,
    :ver
  ]

  def is_idle?(device) do
    device.state == @idle
  end

  def set_idle(device) do
    %{device | state: @idle, user_id: nil}
  end

  def set_requesting(device, user_id) do
    if device.state == @idle do
      {:ok, %{device | state: @requesting, user_id: user_id}}
    else
      {:error, :invalid_state}
    end
  end

  def set_using(device) do
    if device.state == @requesting do
      {:ok, %{device | state: @using}}
    else
      {:error, :invalid_state}
    end
  end

  @doc """
  Detect whether the device matches the filters
  """
  def match(device, filters) do
    res =
      Enum.reject(filters, fn {key, value} ->
        if blank?(value) do
          true
        else
          case String.to_atom(key) do
            :cpu -> device.cpu == value
            :gpu -> device.gpu == value
            :ram -> device.ram >= value
            _ -> true
          end
        end
      end)

    Enum.empty?(res)
  end

  @doc """
  Return field map with value list for user selection.
  Only free device can be selected.
  """
  def select_fields(devices) when is_list(devices) do
    {cpu, ram, gpu} =
      List.foldl(devices, {[], [], []}, fn device, {cpu, ram, gpu} = acc ->
        if is_idle?(device) do
          cpu = unless blank?(device.cpu), do: [device.cpu | cpu], else: cpu
          ram = unless blank?(device.ram), do: [device.ram | ram], else: ram
          gpu = unless blank?(device.gpu), do: [device.gpu | gpu], else: gpu

          {cpu, ram, gpu}
        else
          acc
        end
      end)

    %{
      cpu: cpu |> Enum.uniq(),
      ram: ram |> Enum.uniq(),
      gpu: gpu |> Enum.uniq()
    }
  end

  def blank?(value) when is_binary(value) do
    byte_size(value) == 0
  end

  def blank?(value) when is_integer(value) do
    value == 0
  end

  def blank?(nil), do: true
end
