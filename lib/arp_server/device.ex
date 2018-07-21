defmodule ARP.Device do
  @moduledoc """
  Define a device struct to record online device.
  """

  # state value
  @pending 0
  @idle 1
  @requesting 2
  @using 3

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

  def is_pending?(device) do
    device.state == @pending
  end

  def is_idle?(device) do
    device.state == @idle
  end

  def set_pending(device) do
    %{device | state: @pending}
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
          case key do
            :cpu -> device.cpu == value
            :gpu -> device.gpu == value
            :ram -> device.ram >= value
            :upload_speed -> device.upload_speed >= value
            :download_speed -> device.download_speed >= value
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
    fields = [:cpu, :ram, :gpu, :upload_speed, :download_speed]

    res =
      List.foldl(devices, %{}, fn device, acc ->
        if is_idle?(device) do
          for field <- fields, v = Map.get(device, field), !blank?(v), into: %{} do
            {field, [v | acc[field] || []]}
          end
        else
          acc
        end
      end)

    for {k, v} <- res, into: %{} do
      {k, v |> Enum.uniq()}
    end
  end

  def blank?(value) when is_binary(value) do
    byte_size(value) == 0
  end

  def blank?(value) when is_integer(value) do
    value == 0
  end

  def blank?(nil), do: true
end
