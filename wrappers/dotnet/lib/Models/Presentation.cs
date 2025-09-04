using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Models;

public sealed class Presentation : AnonCredsObject
{
    private Presentation(long handle)
        : base(handle) { }

    public static Presentation Create(
        long presReqHandle,
        FfiCredentialEntryList credentialsList,
        FfiCredentialProveList credentialsProve,
        FfiStrList selfAttestNames,
        FfiStrList selfAttestValues,
        string linkSecret,
        FfiObjectHandleList schemasList,
        FfiStrList schemaIds,
        FfiObjectHandleList credDefsList,
        FfiStrList credDefIds
    )
    {
        if (
            presReqHandle == 0
            || string.IsNullOrEmpty(linkSecret)
            || schemasList.Count == 0
            || credDefsList.Count == 0
            || schemaIds.Count == 0
            || credDefIds.Count == 0
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");

        try
        {
            var code = NativeMethods.anoncreds_create_presentation(
                presReqHandle,
                credentialsList,
                credentialsProve,
                selfAttestNames,
                selfAttestValues,
                linkSecret,
                schemasList,
                schemaIds,
                credDefsList,
                credDefIds,
                out var handle
            );

            if (code != ErrorCode.Success)
            {
                var errorMsg = AnonCredsHelpers.GetCurrentError();
                throw new AnonCredsException(code, errorMsg);
            }
            return new Presentation(handle);
        }
        finally
        {
            AnonCredsHelpers.FreeFfiObjectHandleList(schemasList);
            AnonCredsHelpers.FreeFfiObjectHandleList(credDefsList);
            AnonCredsHelpers.FreeFfiCredentialEntryList(credentialsList);
            AnonCredsHelpers.FreeFfiCredentialProveList(credentialsProve);
        }
    }

    public static Presentation FromJson(string json) => FromJson<Presentation>(json);
}
