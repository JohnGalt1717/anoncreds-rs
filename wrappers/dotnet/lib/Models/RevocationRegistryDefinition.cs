using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Models;

public class RevocationRegistryDefinition : AnonCredsObject
{
    internal RevocationRegistryDefinition(long handle)
        : base(handle) { }

    public static (RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate) Create(
        CredentialDefinition credDef,
        string credDefId,
        string issuerId,
        string tag,
        string revType,
        int maxCredNum,
        string? tailsPath = null
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
            out var _
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return (
            new RevocationRegistryDefinition(def),
            new RevocationRegistryDefinitionPrivate(pvt)
        );
    }

    public string TailsLocation
    {
        get
        {
            var json = ToJson();
            var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("tails_location", out var tailsLocation))
            {
                return tailsLocation.GetString() ?? "";
            }
            return "";
        }
    }

    public static RevocationRegistryDefinition FromJson(string json) =>
        FromJson<RevocationRegistryDefinition>(json);
}
