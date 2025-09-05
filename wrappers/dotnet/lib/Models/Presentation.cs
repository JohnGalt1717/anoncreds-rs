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
            // Debug: dump credential entries to validate timestamp/rev_state pairing
            try
            {
                var count = (int)credentialsList.Count.ToUInt32();
                Console.WriteLine($"[DEBUG] CredentialsList count: {count}");
                if (credentialsList.Data != IntPtr.Zero)
                {
                    var size =
                        System.Runtime.InteropServices.Marshal.SizeOf<AnonCredsNet.Interop.FfiCredentialEntry>();
                    for (int i = 0; i < count; i++)
                    {
                        var ptr = credentialsList.Data + (i * size);
                        var e =
                            System.Runtime.InteropServices.Marshal.PtrToStructure<AnonCredsNet.Interop.FfiCredentialEntry>(
                                ptr
                            );
                        Console.WriteLine(
                            $"[DEBUG] Entry {i}: cred={e.Credential}, ts={e.Timestamp}, revState={e.RevState}"
                        );
                    }
                }
            }
            catch { }
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

    public static Presentation CreateFromJson(
        PresentationRequest presReq,
        string credentialsJson,
        string? selfAttestJson,
        string linkSecret,
        string schemasJson,
        string credDefsJson,
        string schemaIdsJson,
        string credDefIdsJson,
        string? revRegsJson,
        string? revListsJson
    )
    {
        var (schemasList, _) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
            schemasJson,
            Schema.FromJson
        );
        var (credDefsList, _) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
            credDefsJson,
            CredentialDefinition.FromJson
        );
        var credentialsList = AnonCredsHelpers.ParseCredentialsJson(credentialsJson);
        var schemaIds = AnonCredsHelpers.CreateFfiStrList(schemaIdsJson);
        var credDefIds = AnonCredsHelpers.CreateFfiStrList(credDefIdsJson);

        var credentialsProve = AnonCredsHelpers.CreateCredentialsProveList(
            presReq.ToJson(),
            selfAttestJson,
            credentialsJson
        );

        var selfAttestNames = new FfiStrList();
        var selfAttestValues = new FfiStrList();
        if (!string.IsNullOrEmpty(selfAttestJson))
        {
            var selfAttested =
                System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(
                    selfAttestJson!
                ) ?? new();
            selfAttestNames = AnonCredsHelpers.CreateFfiStrListFromStrings(
                selfAttested.Keys.ToArray()
            );
            selfAttestValues = AnonCredsHelpers.CreateFfiStrListFromStrings(
                selfAttested.Values.ToArray()
            );
        }

        return Create(
            presReq.Handle,
            credentialsList,
            credentialsProve,
            selfAttestNames,
            selfAttestValues,
            linkSecret,
            schemasList,
            schemaIds,
            credDefsList,
            credDefIds
        );
    }

    public bool Verify(
        PresentationRequest presReq,
        string schemasJson,
        string credDefsJson,
        string schemaIdsJson,
        string credDefIdsJson,
        string? revRegDefsJson = null,
        string? revStatusListsJson = null,
        string? revRegDefIdsJson = null,
        string? nonRevocJson = null
    )
    {
        return AnonCredsHelpers.VerifyPresentation(
            this,
            presReq,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegDefsJson,
            revStatusListsJson,
            revRegDefIdsJson,
            nonRevocJson
        );
    }
}
