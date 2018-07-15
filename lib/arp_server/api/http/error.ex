defmodule ARP.API.HTTP.Error do
  @moduledoc """
  Conveniences for working with error codes and create error object.
  """

  codes = %{
    100 => "Other Error",
    101 => "Invalid Param",
    201 => "No Free Device"
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
      %{"code" => unquote(code), "message" => msg || unquote(codes[code])}
    end
  end
end
