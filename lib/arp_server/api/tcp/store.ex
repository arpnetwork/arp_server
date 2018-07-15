defmodule ARP.API.TCP.Store do
  @moduledoc """
  Store device socket

  ## Examples
      iex> alias ARP.API.TCP.Store
      iex> Store.start_link([])
      iex> Store.get(:a)
      nil
      iex> Store.put(:a, :b)
      :ok
      iex> Store.get(:a)
      :b
      iex> Store.get(:b)
      :a
      iex> Store.has_key?(:a)
      true
      iex> Store.delete(:a)
      :ok
      iex> Store.has_key?(:a)
      false
      iex> Store.put(:a, :b)
      :ok
      iex> Store.delete(:b)
      :ok
      iex> Store.get(:a)
      nil
  """

  use Agent

  def start_link(_opts) do
    Agent.start_link(fn -> Map.new() end, name: __MODULE__)
  end

  def get(key) do
    Agent.get(__MODULE__, &Map.get(&1, key))
  end

  def put(key, value) do
    Agent.update(__MODULE__, &(Map.put(&1, key, value) |> Map.put(value, key)))
  end

  def delete(key) do
    Agent.update(__MODULE__, fn items ->
      {value, items} = Map.get_and_update(items, key, fn _ -> :pop end)
      Map.delete(items, value)
    end)
  end

  def has_key?(key) do
    Agent.get(__MODULE__, &Map.has_key?(&1, key))
  end
end
