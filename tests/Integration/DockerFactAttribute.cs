using System.Net.Sockets;

namespace Snail.Toolkit.HashiCorp.Vault.Tests.Integration;

/// <summary>
/// A fact that runs only when a Docker daemon answers, and skips otherwise — unless
/// <c>VAULT_TESTS_REQUIRE_DOCKER</c> is set, which is how a pipeline refuses to pass by skipping.
/// </summary>
public sealed class DockerFactAttribute : FactAttribute
{
    private static readonly bool Required =
        Environment.GetEnvironmentVariable("VAULT_TESTS_REQUIRE_DOCKER") is { Length: > 0 } and not "0";

    private static readonly bool Available = CanReachDocker();

    public DockerFactAttribute()
    {
        if (!Available && !Required)
            Skip = "Docker is not available.";
    }

    /// <summary>Connects to the daemon socket instead of trusting the file to be there.</summary>
    /// <remarks>
    /// A stopped Docker Desktop leaves its socket file behind, so a file check reports a daemon that is
    /// not running and the whole integration suite fails where it was meant to skip.
    /// </remarks>
    private static bool CanReachDocker()
    {
        if (Environment.GetEnvironmentVariable("DOCKER_HOST") is { Length: > 0 })
            return true;

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        return Answers("/var/run/docker.sock") || Answers($"{home}/.docker/run/docker.sock");
    }

    private static bool Answers(string socketPath)
    {
        if (!File.Exists(socketPath))
            return false;

        try
        {
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            socket.Connect(new UnixDomainSocketEndPoint(socketPath));

            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
