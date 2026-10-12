using BenchmarkDotNet.Attributes;
using Snail.Toolkit.HashiCorp.Vault.Http;

namespace Snail.Toolkit.HashiCorp.Vault.Benchmarks;

/// <summary>
/// The two reads a process makes of Vault: the full load of five secrets into flat configuration at start-up and on a
/// change, and the periodic check that reads only each secret's version, for the life of the process.
/// </summary>
[MemoryDiagnoser]
public class Loading
{
    private VaultOptions _options = null!;

    private VaultHttpClient _reader = null!;

    private VaultConfigurationProvider _loaded = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _options = CannedVault.Options();
        _reader = new VaultHttpClient(_options, CannedVault.Client());
        _loaded = new VaultConfigurationProvider(_options, _reader);
        _loaded.Load();

        if (await _reader.ReadSecretVersionAsync(_options.Secrets![0]).ConfigureAwait(false) != 7)
            throw new InvalidOperationException("The version probe did not read the version the metadata carries.");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _loaded.Dispose();
        _reader.Dispose();
    }

    [Benchmark]
    public void FullLoad() => new VaultConfigurationProvider(_options, _reader).Load();

    [Benchmark]
    public Task ReloadCheck() => _loaded.ReloadAsync(CancellationToken.None);
}
