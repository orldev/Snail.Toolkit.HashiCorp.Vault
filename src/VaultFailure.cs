using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Snail.Toolkit.HttpBuilder.Extensions;

namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>What a failed load says: whether waiting could help, and whether the configuration is to blame.</summary>
/// <remarks>
/// The two questions are deliberately of opposite shape. <see cref="IsTransient"/> is a list, because only a
/// listed few failures can answer "yes" to "could waiting help", and a failure nobody anticipated has to fail
/// with its own message instead of spending the load budget and reporting a Vault timeout that never happened.
/// <see cref="IsPermanent"/> is the mistakes <c>Optional</c> must not hide, and everything that is not one of
/// them has to let the application start.
/// </remarks>
internal static class VaultFailure
{
    /// <summary>A failure worth waiting out: the network or the server, never the configuration.</summary>
    /// <remarks>
    /// A refused status is read by its number: Vault answers 429, 472, 473, 501 and 503 while it stands by,
    /// is sealed or is not yet initialised, and the rest of the 4xx range is the credentials or the policy,
    /// which no amount of waiting repairs. A body that is not JSON at all is a proxy answering for a Vault
    /// that is away, the HTML of a maintenance page, and is waited out like a refused connection; an answer
    /// of the wrong shape fails as InvalidOperationException and is not. TaskCanceledException here is one
    /// request timing out on its own; the budget running out is told apart by the caller's token, not by
    /// the exception.
    /// </remarks>
    public static bool IsTransient(Exception exception) => exception switch
    {
        HttpBuilderException refused => IsWorthWaitingFor(refused.StatusCode),
        HttpRequestException or IOException or SocketException or TimeoutException or TaskCanceledException => true,
        JsonException => true,
        _ => false,
    };

    /// <summary>A failure Optional must not hide: the configuration is wrong, not the server away.</summary>
    /// <remarks>
    /// A refused 4xx is that mistake: a token Vault turns away is as much the configuration's fault as a
    /// path it does not have.
    /// </remarks>
    public static bool IsPermanent(Exception exception) => exception switch
    {
        SecretNotFoundException or InvalidOperationException => true,
        HttpBuilderException refused => !IsWorthWaitingFor(refused.StatusCode),
        _ => false,
    };

    /// <summary>Whether a refused status is one Vault answers while unavailable, rather than one it answers to a wrong request.</summary>
    private static bool IsWorthWaitingFor(HttpStatusCode? status) =>
        status is null
            or >= HttpStatusCode.InternalServerError
            or HttpStatusCode.TooManyRequests
            or (HttpStatusCode)472
            or (HttpStatusCode)473;
}
