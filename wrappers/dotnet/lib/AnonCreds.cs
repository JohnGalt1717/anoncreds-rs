using AnonCredsNet.Helpers;

namespace AnonCredsNet;

/// <summary>
/// Small utility surface mirroring python-style helpers.
/// </summary>
public static class AnonCreds
{
    public static string GenerateNonce() => AnonCredsHelpers.GenerateNonce();
}
