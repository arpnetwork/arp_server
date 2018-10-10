defmodule ARP.Utils do
  @moduledoc """
  Util functions.
  """

  @doc """
  Decode hex string to integer

  ## Examples
      iex> ARP.Utils.decode_hex("0xa1b2")
      41394
      iex> ARP.Utils.decode_hex("a1b2")
      41394
      iex> ARP.Utils.decode_hex("1b2")
      434
      iex> ARP.Utils.decode_hex("0xA1b2")
      41394
  """
  @spec decode_hex(String.t()) :: integer()
  def decode_hex(string) do
    string = String.trim_leading(string, "0x")
    len = String.length(string)

    string
    |> String.pad_leading(len + Integer.mod(len, 2), "0")
    |> Base.decode16!(case: :mixed)
    |> :binary.decode_unsigned(:big)
  end

  @doc """
  Encode integer to hex string
  """
  def encode_integer(int) do
    hex = int |> :binary.encode_unsigned() |> Base.encode16(case: :lower)
    "0x" <> hex
  end

  def ip_to_integer(ip) do
    [head | tail] = String.split(ip, ".")
    first = String.to_integer(head) * 256 * 256 * 256
    [head | tail] = tail
    second = String.to_integer(head) * 256 * 256
    [head | tail] = tail
    third = String.to_integer(head) * 256
    [head | _] = tail
    fourth = String.to_integer(head)
    first + second + third + fourth
  end
end
