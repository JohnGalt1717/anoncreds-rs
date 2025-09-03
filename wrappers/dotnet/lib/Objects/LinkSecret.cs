using System.Runtime.InteropServices;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Objects;

public sealed class LinkSecret : IDisposable
{
    public string Value { get; private set; }

    private LinkSecret(string value)
    {
        Value = value;
    }

    public static LinkSecret Create()
    {
        var code = NativeMethods.anoncreds_create_link_secret(out var secretPtr);
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        var secret =
            Marshal.PtrToStringUTF8(secretPtr)
            ?? throw new InvalidOperationException("Null link secret");
        NativeMethods.anoncreds_string_free(secretPtr);
        return new LinkSecret(secret);
    }

    internal static LinkSecret FromJson(string json)
    {
        // For now, assume the JSON contains the secret value directly
        // This might need adjustment based on the actual JSON format
        return new LinkSecret(json.Trim('"'));
    }

    public void Dispose()
    {
        // LinkSecret doesn't have native resources to dispose
        // since it's just a string value
    }
}
