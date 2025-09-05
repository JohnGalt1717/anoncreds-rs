using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Models;

public sealed class W3cPresentation : AnonCredsObject
{
    private W3cPresentation(long handle)
        : base(handle) { }

    public static W3cPresentation Create(
        long presReqHandle,
        FfiCredentialEntryList credentialsList,
        FfiCredentialProveList credentialsProve,
        string linkSecret,
        FfiObjectHandleList schemasList,
        FfiStrList schemaIds,
        FfiObjectHandleList credDefsList,
        FfiStrList credDefIds,
        string? w3cVersion = null
    )
    {
        if (presReqHandle == 0 || string.IsNullOrEmpty(linkSecret))
            throw new ArgumentNullException("Invalid inputs");
        try
        {
            var code = NativeMethods.anoncreds_create_w3c_presentation(
                presReqHandle,
                credentialsList,
                credentialsProve,
                linkSecret,
                schemasList,
                schemaIds,
                credDefsList,
                credDefIds,
                w3cVersion ?? "1.1",
                out var handle
            );
            if (code != ErrorCode.Success)
                throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
            return new W3cPresentation(handle);
        }
        finally
        {
            AnonCredsHelpers.FreeFfiObjectHandleList(schemasList);
            AnonCredsHelpers.FreeFfiObjectHandleList(credDefsList);
            AnonCredsHelpers.FreeFfiCredentialEntryList(credentialsList);
            AnonCredsHelpers.FreeFfiCredentialProveList(credentialsProve);
        }
    }
}
