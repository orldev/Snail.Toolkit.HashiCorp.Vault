using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Time.Testing;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

/// <summary>
/// Deliberately hostile input, concurrency and dependency failure. Everything here is meant to break the
/// provider, not to confirm that it works.
/// </summary>
public class CrashTests
{
    private static VaultOptions Options(params VaultSecret[] secrets) => new()
    {
        Address = "http://vault.local:8200",
        MountPath = "secret",
        Logger = (_, _) => { },
        Secrets = secrets,
    };

    private static VaultConfigurationProvider Loaded(VaultOptions options, FakeVaultReader reader)
    {
        var provider = new VaultConfigurationProvider(options, reader);
        provider.Load();
        return provider;
    }

    /// <summary>
    /// A secret key that itself contains the configuration separator would land as a section boundary
    /// and shadow a key mapped from a real nested object. The load has to refuse instead.
    /// </summary>
    [Fact]
    public void Load_KeyCarryingTheSeparatorIsRefused()
    {
        var reader = new FakeVaultReader()
            .Set("app", 1, """{"Nested:Inner": "injected", "Nested": {"Inner": "genuine"}}""");

        var error = Assert.Throws<InvalidOperationException>(
            () => Loaded(Options(new VaultSecret(Path: "app")), reader));

        Assert.Contains("app:Nested:Inner", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Vault allows two keys differing only in case; configuration keys are case-insensitive, so one of
    /// them would disappear without a word.
    /// </summary>
    [Fact]
    public void Load_KeysDifferingOnlyInCaseAreRefused()
    {
        var reader = new FakeVaultReader()
            .Set("app", 1, """{"Token": "first", "TOKEN": "second"}""");

        var error = Assert.Throws<InvalidOperationException>(
            () => Loaded(Options(new VaultSecret(Path: "app")), reader));

        Assert.Contains("Token", error.Message, StringComparison.Ordinal);
        Assert.Contains("TOKEN", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Emoji, an escaped NUL, a tab and a very long value all have to reach the application unchanged.
    /// </summary>
    [Fact]
    public void Load_HostileTextSurvivesUnchanged()
    {
        var huge = new string('x', 1_000_000);
        var reader = new FakeVaultReader()
            .Set("app", 1, $$"""{"Emoji": "\ud83d\udd10", "Control": "a\u0000b\tc", "Huge": "{{huge}}"}""");

        using var provider = Loaded(Options(new VaultSecret(Path: "app")), reader);

        Assert.True(provider.TryGet("app:Emoji", out var emoji));
        Assert.Equal("\ud83d\udd10", emoji);
        Assert.True(provider.TryGet("app:Control", out var control));
        Assert.Equal("a\0b\tc", control);
        Assert.True(provider.TryGet("app:Huge", out var value));
        Assert.Equal(1_000_000, value!.Length);
    }

    /// <summary>
    /// The flattener recurses per level. A value carrying a document nested deeper than the parser allows
    /// must not reach it as a parsed tree, or the recursion overflows the stack and kills the process.
    /// </summary>
    [Fact]
    public void Load_ValueNestedDeeperThanTheParserAllowsStaysText()
    {
        var deep = string.Concat(Enumerable.Repeat("[", 5000)) + string.Concat(Enumerable.Repeat("]", 5000));
        var reader = new FakeVaultReader()
            .Set("app", 1, System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, string> { ["Deep"] = deep }));

        using var provider = Loaded(Options(new VaultSecret(Path: "app")), reader);

        Assert.True(provider.TryGet("app:Deep", out var value));
        Assert.Equal(deep, value);
    }

    /// <summary>
    /// A secret holding a large array turns into one configuration entry per element.
    /// </summary>
    [Fact]
    public void Load_LargeArrayDoesNotDegradeIntoSomethingWorseThanItsSize()
    {
        var elements = string.Join(",", Enumerable.Range(0, 50_000).Select(i => $"\"v{i}\""));
        var reader = new FakeVaultReader().Set("app", 1, $$"""{"Many": [{{elements}}]}""");

        using var provider = Loaded(Options(new VaultSecret(Path: "app")), reader);

        Assert.True(provider.TryGet("app:Many:49999", out var last));
        Assert.Equal("v49999", last);
    }

    /// <summary>
    /// Readers hammering TryGet while the background swaps Data must never see a torn or absent value.
    /// </summary>
    [Fact]
    public async Task Reload_ConcurrentReadersNeverSeeAMissingKey()
    {
        var reader = new FakeVaultReader().Set("mongo", 1, """{"Connection": "a"}""");
        using var provider = Loaded(Options(new VaultSecret(Path: "mongo")), reader);

        var failures = new ConcurrentBag<string>();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        var readers = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                if (!provider.TryGet("mongo:Connection", out var value) || value is null)
                    failures.Add("key vanished during a reload");
            }
        })).ToArray();

        var version = 1;
        while (!stop.IsCancellationRequested)
        {
            reader.Set("mongo", ++version, $$"""{"Connection": "value{{version}}"}""");
            await provider.ReloadAsync(CancellationToken.None);
        }

        await Task.WhenAll(readers);

        Assert.Empty(failures);
    }

    /// <summary>
    /// Many requests arriving together on an expired lease must produce one login, not one each.
    /// </summary>
    [Fact]
    public async Task Login_FiftyConcurrentReadsShareASingleRenewal()
    {
        var handler = new LeasedVaultHandler(leaseSeconds: 3600);
        var options = Options();
        options.Token = null;
        options.RoleId = "role";
        options.SecretId = "secret";
        using var client = new Http.VaultHttpClient(
            options, new HttpClient(handler) { BaseAddress = new Uri("http://vault.local:8200/") });

        await Task.WhenAll(Enumerable.Range(0, 50)
            .Select(_ => client.ReadSecretAsync(new VaultSecret(Path: "mongo"))));

        Assert.Equal(1, handler.Logins);
    }

    /// <summary>
    /// One secret failing halfway through must leave the previously loaded values alone rather than
    /// publishing a half-built configuration.
    /// </summary>
    [Fact]
    public async Task Reload_FailureOnTheSecondSecretKeepsTheOldValues()
    {
        var reader = new FakeVaultReader()
            .Set("first", 1, """{"A": "one"}""")
            .Set("second", 1, """{"B": "two"}""");
        var options = Options(new VaultSecret(Path: "first"), new VaultSecret(Path: "second"));

        using var provider = Loaded(options, reader);
        reader.Set("first", 2, """{"A": "changed"}""");
        reader.FailuresByPath["second"] = new HttpRequestException("vault went away");

        await Assert.ThrowsAsync<HttpRequestException>(() => provider.ReloadAsync(CancellationToken.None));

        Assert.True(provider.TryGet("first:A", out var first));
        Assert.Equal("one", first);
        Assert.True(provider.TryGet("second:B", out var second));
        Assert.Equal("two", second);
    }

    /// <summary>
    /// A dependency deaf to cancellation must not hold shutdown open indefinitely.
    /// </summary>
    [Fact]
    public void Dispose_ReaderThatIgnoresCancellationStillLetsShutdownFinish()
    {
        var reader = new FakeVaultReader().Set("mongo", 1, """{"Connection": "a"}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.ReloadCheckIntervalSeconds = 1;

        var provider = Loaded(options, reader);
        reader.IgnoresCancellation = true;
        reader.Latency = TimeSpan.FromSeconds(30);
        Thread.Sleep(TimeSpan.FromSeconds(1.5));

        var elapsed = Stopwatch.StartNew();
        provider.Dispose();
        elapsed.Stop();

        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(8), $"Dispose took {elapsed.Elapsed}");
    }

    /// <summary>
    /// Disposing while the first load is still running must not leave a refresh loop behind it.
    /// </summary>
    [Fact]
    public async Task Dispose_RacingTheFirstLoadLeavesNoRefreshBehind()
    {
        var reader = new FakeVaultReader { Latency = TimeSpan.FromMilliseconds(300) }
            .Set("mongo", 1, """{"Connection": "a"}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.ReloadCheckIntervalSeconds = 1;
        var time = new FakeTimeProvider();

        var provider = new VaultConfigurationProvider(options, reader, time);
        var loading = Task.Run(provider.Load);

        await Task.Delay(150);
        provider.Dispose();
        await loading;

        reader.Latency = TimeSpan.Zero;
        var afterDispose = reader.Attempts;
        time.Advance(TimeSpan.FromSeconds(3));
        await Task.Delay(50);

        Assert.Equal(afterDispose, reader.Attempts);
    }

    /// <summary>
    /// A secret whose payload is an empty object must not wipe the section it maps to.
    /// </summary>
    [Fact]
    public void Load_EmptyPayloadIsNotATotalLoss()
    {
        var reader = new FakeVaultReader().Set("app", 1, "{}");

        using var provider = Loaded(Options(new VaultSecret(Path: "app")), reader);

        Assert.False(provider.TryGet("app", out _));
    }

    /// <summary>
    /// Two secrets aimed at the same section: the later one wins silently, which is worth knowing.
    /// </summary>
    [Fact]
    public void Load_TwoSecretsOnOneSectionResolveDeterministically()
    {
        var reader = new FakeVaultReader()
            .Set("first", 1, """{"Shared": "from-first"}""")
            .Set("second", 1, """{"Shared": "from-second"}""");
        var options = Options(
            new VaultSecret(Path: "first", ConfigurationPrefix: "Same"),
            new VaultSecret(Path: "second", ConfigurationPrefix: "Same"));

        using var provider = Loaded(options, reader);

        Assert.True(provider.TryGet("Same:Shared", out var value));
        Assert.Equal("from-second", value);
    }
}
