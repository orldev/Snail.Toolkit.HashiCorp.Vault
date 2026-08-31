namespace Snail.Toolkit.HashiCorp.Vault.Tests.Integration;

/// <summary>
/// A fact that runs only when a Docker daemon is reachable; otherwise the test is skipped
/// instead of failing on the missing socket.
/// </summary>
public sealed class DockerFactAttribute : FactAttribute
{
    private static readonly bool DockerAvailable =
        File.Exists("/var/run/docker.sock") ||
        File.Exists($"{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}/.docker/run/docker.sock") ||
        Environment.GetEnvironmentVariable("DOCKER_HOST") is not null;

    public DockerFactAttribute()
    {
        if (!DockerAvailable)
            Skip = "Docker is not available.";
    }
}
