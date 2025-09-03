using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Objects;

public sealed class Credential : AnonCredsObject
{
    private Credential(UIntPtr handle)
        : base(handle) { }

    /// <summary>
    /// Creates a credential and its revocation delta. Both returned objects must be disposed using <c>using</c> statements.
    /// </summary>
    internal static (Credential Credential, RevocationStatusListDelta? Delta) Create(
        CredentialDefinition credDef,
        CredentialDefinitionPrivate credDefPvt,
        CredentialOffer offer,
        CredentialRequest request,
        string credValues,
        string? revRegId,
        string? tailsPath,
        RevocationStatusList? revStatusList
    )
    {
        if (
            credDef == null
            || credDefPvt == null
            || offer == null
            || request == null
            || string.IsNullOrEmpty(credValues)
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");

        // Parse credential values JSON
        var credValuesDict = System.Text.Json.JsonSerializer.Deserialize<
            Dictionary<string, string>
        >(credValues);
        if (credValuesDict == null)
            throw new ArgumentException("Invalid credential values JSON");

        var attrNames = AnonCredsHelpers.CreateFfiStrList(
            System.Text.Json.JsonSerializer.Serialize(credValuesDict.Keys)
        );
        var attrRawValues = AnonCredsHelpers.CreateFfiStrList(
            System.Text.Json.JsonSerializer.Serialize(credValuesDict.Values)
        );
        var attrEncValues = AnonCredsHelpers.CreateFfiStrList(
            System.Text.Json.JsonSerializer.Serialize(
                Enumerable.Repeat<string?>(null, credValuesDict.Count)
            )
        );

        try
        {
            var code = NativeMethods.anoncreds_create_credential(
                credDef.Handle,
                credDefPvt.Handle,
                offer.Handle,
                request.Handle,
                attrNames,
                attrRawValues,
                attrEncValues,
                IntPtr.Zero, // No revocation config for now
                out var cred
            );
            if (code != ErrorCode.Success)
                throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
            return (new Credential(cred), null); // No delta when not using revocation
        }
        finally
        {
            AnonCredsHelpers.FreeFfiStrList(attrNames);
            AnonCredsHelpers.FreeFfiStrList(attrRawValues);
            AnonCredsHelpers.FreeFfiStrList(attrEncValues);
        }
    }

    internal static Credential Process(
        Credential credential,
        CredentialRequestMetadata metadata,
        LinkSecret linkSecret,
        CredentialDefinition credDef,
        RevocationRegistryDefinition? revRegDef
    )
    {
        if (credential == null || metadata == null || linkSecret == null || credDef == null)
            throw new ArgumentNullException("Input parameters cannot be null");
        if (credential.Handle == UIntPtr.Zero)
            throw new ObjectDisposedException(nameof(Credential));
        var code = NativeMethods.anoncreds_process_credential(
            credential.Handle,
            metadata.Handle,
            linkSecret.Value,
            credDef.Handle,
            revRegDef?.Handle ?? UIntPtr.Zero,
            out var processed
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return new Credential(processed);
    }

    internal static Credential FromJson(string json) => FromJson<Credential>(json);
}
