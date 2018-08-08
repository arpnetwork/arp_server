defmodule ARP.API.JSONRPC2.Handler do
  use JSONRPC2.Server.Handler

  def handle_request(method, params) do
    {module, fun} = parse(method)
    apply(module, fun, params)
  end

  defp parse(method) do
    [module, fun] = String.split(method, "_")

    module = Module.safe_concat([ARP, String.capitalize(module)])

    fun = Macro.underscore(fun) |> String.to_existing_atom()

    {module, fun}
  end
end
