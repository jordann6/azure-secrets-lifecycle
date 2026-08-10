# frozen_string_literal: true

RSpec.describe Scanner::Pool do
  it "returns every worker's results" do
    result = described_class.new(concurrency: 4).map(1..10) { |n| n * 2 }

    expect(result.values.sort).to eq((1..10).map { |n| n * 2 })
    expect(result.errors).to be_empty
    expect(result).not_to be_partial
  end

  it "flattens a worker that returns a batch" do
    result = described_class.new(concurrency: 2).map([1, 2]) { |n| [n, n] }

    expect(result.values.size).to eq(4)
  end

  it "drops nils so a sweep can skip an item without a sentinel value" do
    result = described_class.new(concurrency: 2).map([1, 2, 3]) { |n| n.odd? ? n : nil }

    expect(result.values.sort).to eq([1, 3])
  end

  it "collects a failure instead of losing the whole sweep to it" do
    # One unreachable vault must not cost the scan every other vault's
    # inventory. This is the behaviour that makes a partial scan useful.
    result = described_class.new(concurrency: 2).map(%w[good bad other]) do |item|
      raise Azure::Client::Error, "boom" if item == "bad"

      item
    end

    expect(result.values.sort).to eq(%w[good other])
    expect(result.errors.size).to eq(1)
    expect(result.errors.first[:error]).to include("boom")
    expect(result).to be_partial
  end

  it "never runs more threads than the bound allows" do
    running = Concurrent::AtomicFixnum.new(0)
    peak = Concurrent::AtomicFixnum.new(0)

    described_class.new(concurrency: 3).map(1..30) do
      current = running.increment
      peak.update { |p| [p, current].max }
      sleep 0.01
      running.decrement
    end

    expect(peak.value).to be <= 3
  end

  it "handles an empty work list without spawning anything" do
    result = described_class.new(concurrency: 4).map([]) { raise "never called" }

    expect(result.values).to be_empty
    expect(result.errors).to be_empty
  end

  it "treats a concurrency below one as one" do
    result = described_class.new(concurrency: 0).map([1, 2]) { |n| n }

    expect(result.values.sort).to eq([1, 2])
  end
end
