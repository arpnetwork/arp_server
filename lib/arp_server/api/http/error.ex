defmodule ARP.API.HTTP.Error do
  @moduledoc """
  Conveniences for working with error codes and create error object.
  """

  codes = %{
    100 => "Unknow error",
    101 => "Invalid params",
    102 => "Network error",
    200 => "Missing keystore",
    201 => "Already imported keystore",
    202 => "Invalid keystore or password",
    203 => "Password error",
    204 => "Missing password",
    205 => "Eth balance is not enough",
    206 => "Arp balance is not enough",
    300 => "Device offline",
    301 => "Unknow address",
    302 => "Missing config",
    303 => "Service already started"
  }

  reason_phrase_to_atom = fn reason_phrase ->
    reason_phrase
    |> String.downcase()
    |> String.replace("'", "")
    |> String.replace(~r/[^a-z0-9]/, "_")
    |> String.to_atom()
  end

  def new(code, msg \\ nil)

  for {code, reason_phrase} <- codes do
    atom = reason_phrase_to_atom.(reason_phrase)

    def new(unquote(atom), msg) do
      %{code: unquote(code), message: msg || unquote(codes[code])}
    end
  end
end
