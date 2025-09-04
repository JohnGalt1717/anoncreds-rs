using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Models;

public class RevocationStatusList : AnonCredsObject
{
    private RevocationStatusList(long handle)
        : base(handle) { }

    public static (
        RevocationRegistryDefinition RevRegDef,
        RevocationRegistryDefinitionPrivate RevRegPvt,
        RevocationStatusList StatusList
    ) CreateRevocationRegistryDefinition(
        CredentialDefinition credDef,
        string credDefId,
        string issuerId,
        string tag,
        string revType,
        long maxCredNum,
        string tailsPath
    )
    {
        if (
            credDef == null
            || string.IsNullOrEmpty(credDefId)
            || string.IsNullOrEmpty(issuerId)
            || string.IsNullOrEmpty(tag)
            || string.IsNullOrEmpty(revType)
            || maxCredNum <= 0
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_create_revocation_registry_def(
            credDef.Handle,
            credDefId,
            issuerId,
            tag,
            revType,
            maxCredNum,
            tailsPath ?? "",
            out var def,
            out var pvt,
            out var list
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return (
            new RevocationRegistryDefinition(def),
            new RevocationRegistryDefinitionPrivate(pvt),
            new RevocationStatusList(list)
        );
    }

    public static RevocationStatusList Create(
        CredentialDefinition credDef,
        string revRegId,
        RevocationRegistryDefinition revRegDef,
        RevocationRegistryDefinitionPrivate revRegDefPrivate,
        string issuerId,
        bool issuanceByDefault,
        ulong timestamp
    )
    {
        if (
            credDef == null
            || string.IsNullOrEmpty(revRegId)
            || revRegDef == null
            || revRegDefPrivate == null
            || string.IsNullOrEmpty(issuerId)
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");

        // Note: This is a simplified implementation. The actual native call may differ.
        // For now, we'll use the existing native call with dummy values.
        var code = NativeMethods.anoncreds_create_revocation_status_list(
            credDef.Handle,
            revRegId,
            revRegDef.Handle,
            revRegDefPrivate.Handle,
            issuerId,
            issuanceByDefault,
            (long)timestamp,
            out var handle
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return new RevocationStatusList(handle);
    }

    public RevocationStatusList Update(
        CredentialDefinition credDef,
        RevocationRegistryDefinition revRegDef,
        RevocationRegistryDefinitionPrivate revRegDefPrivate,
        ulong[]? issued,
        ulong[]? revoked,
        ulong timestamp
    )
    {
        if (credDef == null || revRegDef == null || revRegDefPrivate == null)
            throw new ArgumentNullException("Input parameters cannot be null or empty");

        // Note: This is a simplified implementation. The actual native call may differ.
        // For now, we'll use the existing native call with dummy values.
        var issuedJson = issued != null ? System.Text.Json.JsonSerializer.Serialize(issued) : "{}";
        var revokedJson =
            revoked != null ? System.Text.Json.JsonSerializer.Serialize(revoked) : "{}";

        var code = NativeMethods.anoncreds_update_revocation_status_list(
            credDef.Handle,
            issuedJson,
            revokedJson,
            timestamp.ToString(),
            out var updated,
            out var _
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return new RevocationStatusList(updated);
    }

    public static RevocationStatusList FromJson(string json) =>
        FromJson<RevocationStatusList>(json);
}
