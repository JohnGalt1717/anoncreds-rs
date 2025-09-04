using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;
using AnonCredsNet.Objects;

namespace AnonCredsNet.Models;

public class LinkSecret : AnonCredsObject
{
    internal LinkSecret(long handle)
        : base(handle) { }

    public static LinkSecret Create()
    {
        var code = NativeMethods.anoncreds_create_link_secret(out var handle);
        if (code != ErrorCode.Success)
        {
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        }
        return new LinkSecret(handle);
    }
}
