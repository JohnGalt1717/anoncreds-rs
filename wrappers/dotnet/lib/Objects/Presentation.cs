using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Objects;

public sealed class Presentation : AnonCredsObject
{
    private Presentation(UIntPtr handle)
        : base(handle) { }

    public static Presentation Create(
        UIntPtr presReqHandle,
        FfiCredentialEntryList credentialsList,
        FfiCredentialProveList credentialsProve,
        string? selfAttestJson,
        LinkSecret linkSecret,
        FfiObjectHandleList schemasList,
        FfiStrList schemaIds,
        FfiObjectHandleList credDefsList,
        FfiStrList credDefIds
    )
    {
        Console.WriteLine("      DEBUG: Entering Presentation.Create");
        if (
            presReqHandle == UIntPtr.Zero
            || linkSecret == null
            || schemasList.Count == 0
            || credDefsList.Count == 0
            || schemaIds.Count == 0
            || credDefIds.Count == 0
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");

        Console.WriteLine("      DEBUG: Input validation passed");
        try
        {
            Console.WriteLine("      DEBUG: Parsing self-attested attributes");
            // Parse self-attested attributes
            var selfAttest =
                string.IsNullOrEmpty(selfAttestJson) || selfAttestJson == "{}"
                    ? new Dictionary<string, string>()
                    : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(
                        selfAttestJson
                    ) ?? new Dictionary<string, string>();

            Console.WriteLine("      DEBUG: Creating self-attest names list");
            var selfAttestNames = AnonCredsHelpers.CreateFfiStrList(
                System.Text.Json.JsonSerializer.Serialize(selfAttest.Keys.ToArray())
            );
            Console.WriteLine("      DEBUG: Creating self-attest values list");
            var selfAttestValues = AnonCredsHelpers.CreateFfiStrList(
                System.Text.Json.JsonSerializer.Serialize(selfAttest.Values.ToArray())
            );
            Console.WriteLine("      DEBUG: About to call native anoncreds_create_presentation");

            var code = NativeMethods.anoncreds_create_presentation(
                presReqHandle,
                credentialsList,
                credentialsProve,
                selfAttestNames,
                selfAttestValues,
                linkSecret.Value,
                schemasList,
                schemaIds,
                credDefsList,
                credDefIds,
                out var handle
            );

            Console.WriteLine($"      DEBUG: Native call returned code: {code}");
            // Free the temporary lists
            AnonCredsHelpers.FreeFfiStrList(selfAttestNames);
            AnonCredsHelpers.FreeFfiStrList(selfAttestValues);

            if (code != ErrorCode.Success)
            {
                var errorMsg = AnonCredsHelpers.GetCurrentError();
                Console.WriteLine($"      DEBUG: Native error message: {errorMsg}");
                throw new AnonCredsException(code, errorMsg);
            }
            Console.WriteLine("      DEBUG: Presentation created successfully");
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
