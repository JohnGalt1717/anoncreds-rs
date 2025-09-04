// AnonCredsClient.cs
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;

namespace AnonCredsNet;

public class AnonCredsClient
{
    public AnonCredsClient()
    {
        // Placeholder for initialization if needed
    }

    /// <summary>
    /// Generates a cryptographically secure nonce for use in presentation requests.
    /// </summary>
    public static string GenerateNonce()
    {
        return AnonCredsHelpers.GenerateNonce();
    }

    public Presentation CreatePresentation(
        PresentationRequest presReq,
        string credentialsJson,
        string? selfAttestJson,
        string linkSecret,
        string schemasJson,
        string credDefsJson,
        string? revRegsJson,
        string? revListsJson
    )
    {
        // Derive schema and cred def IDs from the provided JSON maps if not explicitly provided
        string? schemaIdsJson = null;
        string? credDefIdsJson = null;

        try
        {
            var schemaMap = JsonSerializer.Deserialize<Dictionary<string, string>>(schemasJson);
            if (schemaMap != null)
                schemaIdsJson = JsonSerializer.Serialize(schemaMap.Keys.ToArray());
        }
        catch
        { /* leave null if not a map */
        }

        try
        {
            var credDefMap = JsonSerializer.Deserialize<Dictionary<string, string>>(credDefsJson);
            if (credDefMap != null)
                credDefIdsJson = JsonSerializer.Serialize(credDefMap.Keys.ToArray());
        }
        catch
        { /* leave null if not a map */
        }

        var (presentation, _, _, _, _, _, _, _, _, _) = CreatePresentation(
            presReq,
            credentialsJson,
            selfAttestJson,
            linkSecret,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegsJson,
            revListsJson
        );
        return presentation;
    }

    public (
        Presentation presentation,
        FfiStrList schemaIds,
        FfiObjectHandleList schemas,
        FfiStrList credDefIds,
        FfiObjectHandleList credDefs,
        FfiStrList revRegIds,
        FfiObjectHandleList revRegs,
        FfiStrList revListIds,
        FfiObjectHandleList revLists,
        FfiCredentialEntryList credentials
    ) CreatePresentation(
        PresentationRequest presReq,
        string credentialsJson,
        string? selfAttestJson,
        string linkSecret,
        string schemasJson,
        string credDefsJson,
        string? schemaIdsJson,
        string? credDefIdsJson,
        string? revRegsJson,
        string? revListsJson
    )
    {
        Console.WriteLine("   DEBUG: Entering CreatePresentation");
        if (
            presReq == null
            || string.IsNullOrEmpty(credentialsJson)
            || string.IsNullOrEmpty(linkSecret)
            || string.IsNullOrEmpty(schemasJson)
            || string.IsNullOrEmpty(credDefsJson)
            || string.IsNullOrEmpty(schemaIdsJson)
            || string.IsNullOrEmpty(credDefIdsJson)
        )
            throw new ArgumentNullException("Required parameters cannot be null or empty");

        Console.WriteLine("   DEBUG: Creating schemas list from JSON");
        var (schemasList, schemasObjects) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
            schemasJson,
            Schema.FromJson
        );
        Console.WriteLine("   DEBUG: Created schemas list successfully");

        Console.WriteLine("   DEBUG: Creating credDefs list from JSON");
        var (credDefsList, credDefsObjects) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
            credDefsJson,
            CredentialDefinition.FromJson
        );
        Console.WriteLine("   DEBUG: Created credDefs list successfully");

        Console.WriteLine("   DEBUG: Parsing credentials JSON");
        FfiCredentialEntryList credentialsList = ParseCredentialsJson(credentialsJson);
        Console.WriteLine("   DEBUG: Parsed credentials JSON successfully");
        // Debug each entry for timestamp/rev_state presence
        try
        {
            var dbgEntries = System.Text.Json.JsonSerializer.Deserialize<CredentialEntryJson[]>(
                credentialsJson
            );
            if (dbgEntries != null)
            {
                foreach (var e in dbgEntries)
                {
                    Console.WriteLine(
                        $"DEBUG Credentials entry -> Timestamp: {e.Timestamp?.ToString() ?? "<null>"}, RevState: {(string.IsNullOrEmpty(e.RevState) ? 0 : 1)}"
                    );
                }
            }
        }
        catch { }

        Console.WriteLine("   DEBUG: Creating schema IDs list");
        var schemaIds = AnonCredsHelpers.CreateFfiStrList(schemaIdsJson);
        Console.WriteLine("   DEBUG: Created schema IDs list successfully");

        Console.WriteLine("   DEBUG: Creating credDef IDs list");
        var credDefIds = AnonCredsHelpers.CreateFfiStrList(credDefIdsJson);
        Console.WriteLine("   DEBUG: Created credDef IDs list successfully");

        var revRegIds = new FfiStrList();
        var revRegsList = new FfiObjectHandleList();
        var revListsList = new FfiObjectHandleList();

        if (!string.IsNullOrEmpty(revRegsJson))
        {
            var (revRegs, _) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
                revRegsJson,
                RevocationRegistryDefinition.FromJson
            );
            revRegsList = revRegs;
        }

        if (!string.IsNullOrEmpty(revListsJson))
        {
            var (revLists, _) = AnonCredsHelpers.CreateFfiObjectHandleListWithObjects(
                revListsJson,
                RevocationStatusList.FromJson
            );
            revListsList = revLists;
        }

        Console.WriteLine("   DEBUG: Creating credentials prove list");
        // Create credentials_prove list based on presentation request, excluding self-attested referents
        var credentialsProve = CreateCredentialsProveList(presReq.ToJson(), selfAttestJson);
        Console.WriteLine("   DEBUG: Created credentials prove list successfully");

        var selfAttestNames = new FfiStrList();
        var selfAttestValues = new FfiStrList();

        if (!string.IsNullOrEmpty(selfAttestJson))
        {
            var selfAttested =
                JsonSerializer.Deserialize<Dictionary<string, string>>(selfAttestJson)
                ?? new Dictionary<string, string>();
            selfAttestNames = AnonCredsHelpers.CreateFfiStrListFromStrings(
                selfAttested.Keys.ToArray()
            );
            selfAttestValues = AnonCredsHelpers.CreateFfiStrListFromStrings(
                selfAttested.Values.ToArray()
            );
        }

        // Debug: dump first credential entry
        if (credentialsList.Count.ToUInt32() > 0)
        {
            var entryPtr = credentialsList.Data;
            var entry = Marshal.PtrToStructure<FfiCredentialEntry>(entryPtr);
            Console.WriteLine(
                $"DEBUG Credentials entry -> Timestamp: {entry.Timestamp}, RevState: {entry.RevState}"
            );
        }

        var presentation = Presentation.Create(
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

        return (
            presentation,
            schemaIds,
            schemasList,
            credDefIds,
            credDefsList,
            revRegIds,
            revRegsList,
            new FfiStrList(),
            revListsList,
            credentialsList
        );
    }

    public bool VerifyPresentation(
        Presentation presentation,
        PresentationRequest presReq,
        string schemasJson,
        string credDefsJson,
        string? revRegDefsJson,
        string? revStatusListsJson,
        string? nonRevocJson
    )
    {
        // Extract IDs from the objects - this is a temporary approach since the objects don't contain IDs
        // In a real implementation, the IDs should be passed separately
        throw new NotImplementedException("Use overload that accepts ID arrays");
    }

    public bool VerifyPresentation(
        Presentation presentation,
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
            presentation,
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

    public Credential IssueCredential(
        CredentialDefinition credDef,
        CredentialDefinitionPrivate credDefPvt,
        CredentialOffer offer,
        CredentialRequest request,
        string credValues,
        string? revRegId,
        CredentialRevocationConfig? revConfig,
        string? tailsPath
    )
    {
        if (
            credDef == null
            || credDefPvt == null
            || offer == null
            || request == null
            || string.IsNullOrEmpty(credValues)
        )
            throw new ArgumentNullException("Required parameters cannot be null or empty");

        var (credential, _) = Credential.Create(
            credDef,
            credDefPvt,
            offer,
            request,
            credValues,
            revRegId,
            tailsPath,
            revConfig?.RevStatusList
        );
        return credential;
    }

    private static FfiCredentialEntryList ParseCredentialsJson(string credentialsJson)
    {
        var entries =
            JsonSerializer.Deserialize<CredentialEntryJson[]>(
                credentialsJson,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            ) ?? throw new InvalidOperationException("Invalid credentials JSON");
        var ffiEntries = new FfiCredentialEntry[entries.Length];
        for (var i = 0; i < entries.Length; i++)
        {
            var entry = entries[i];
            var credBuffer = AnonCredsHelpers.CreateByteBuffer(entry.Credential);
            long credHandle;
            ErrorCode result;
            try
            {
                result = NativeMethods.anoncreds_credential_from_json(credBuffer, out credHandle);
            }
            finally
            {
                AnonCredsHelpers.FreeByteBuffer(credBuffer);
            }
            if (result != ErrorCode.Success)
                throw new AnonCredsException(result, AnonCredsHelpers.GetCurrentError());

            long revStateHandle = 0;
            if (!string.IsNullOrEmpty(entry.RevState))
            {
                var revStateBuffer = AnonCredsHelpers.CreateByteBuffer(entry.RevState);
                try
                {
                    result = NativeMethods.anoncreds_revocation_state_from_json(
                        revStateBuffer,
                        out revStateHandle
                    );
                }
                finally
                {
                    AnonCredsHelpers.FreeByteBuffer(revStateBuffer);
                }
                if (result != ErrorCode.Success)
                    throw new AnonCredsException(result, AnonCredsHelpers.GetCurrentError());
            }

            ffiEntries[i] = new FfiCredentialEntry
            {
                Credential = credHandle,
                Timestamp = entry.Timestamp ?? -1,
                RevState = revStateHandle,
            };
        }
        var ptr = Marshal.AllocHGlobal(ffiEntries.Length * Marshal.SizeOf<FfiCredentialEntry>());
        for (var i = 0; i < ffiEntries.Length; i++)
        {
            Marshal.StructureToPtr(
                ffiEntries[i],
                ptr + i * Marshal.SizeOf<FfiCredentialEntry>(),
                false
            );
        }
        return new FfiCredentialEntryList { Data = ptr, Count = (nuint)ffiEntries.Length };
    }

    private static FfiCredentialProveList CreateCredentialsProveList(
        string presReqJson,
        string? selfAttestJson
    )
    {
        var proveList = new List<FfiCredentialProve>();

        // Build a set of referents that are satisfied via self-attested values
        HashSet<string> selfAttestedReferents = new(StringComparer.Ordinal);
        if (!string.IsNullOrEmpty(selfAttestJson))
        {
            try
            {
                var map =
                    JsonSerializer.Deserialize<Dictionary<string, string>>(selfAttestJson!)
                    ?? new();
                foreach (var k in map.Keys)
                {
                    selfAttestedReferents.Add(k);
                }
            }
            catch
            {
                // ignore malformed self-attested JSON; treat as none
            }
        }

        using (var doc = JsonDocument.Parse(presReqJson))
        {
            var root = doc.RootElement;

            if (root.TryGetProperty("requested_attributes", out var requestedAttributes))
            {
                foreach (var attr in requestedAttributes.EnumerateObject())
                {
                    var referent = attr.Name;
                    // Skip if this referent is self-attested
                    if (selfAttestedReferents.Contains(referent))
                        continue;
                    proveList.Add(
                        new FfiCredentialProve
                        {
                            EntryIdx = 0,
                            Referent = Marshal.StringToHGlobalAnsi(referent),
                            IsPredicate = 0,
                            Reveal = 1,
                        }
                    );
                }
            }

            if (root.TryGetProperty("requested_predicates", out var requestedPredicates))
            {
                foreach (var pred in requestedPredicates.EnumerateObject())
                {
                    var referent = pred.Name;
                    proveList.Add(
                        new FfiCredentialProve
                        {
                            EntryIdx = 0,
                            Referent = Marshal.StringToHGlobalAnsi(referent),
                            IsPredicate = 1,
                            Reveal = 0,
                        }
                    );
                }
            }
        }

        if (proveList.Count == 0)
        {
            return new FfiCredentialProveList { Data = IntPtr.Zero, Count = 0 };
        }

        var proveArray = proveList.ToArray();
        var size = Marshal.SizeOf<FfiCredentialProve>();
        var ptr = Marshal.AllocHGlobal(size * proveArray.Length);

        for (int i = 0; i < proveArray.Length; i++)
        {
            Marshal.StructureToPtr(proveArray[i], ptr + (i * size), false);
        }

        return new FfiCredentialProveList { Data = ptr, Count = (nuint)proveArray.Length };
    }

    private class CredentialEntryJson
    {
        [JsonPropertyName("credential")]
        public string Credential { get; set; } = "";

        [JsonPropertyName("timestamp")]
        public int? Timestamp { get; set; }

        [JsonPropertyName("rev_state")]
        public string? RevState { get; set; }
    }
}
