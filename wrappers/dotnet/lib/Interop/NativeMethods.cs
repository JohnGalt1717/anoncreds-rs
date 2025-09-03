// NativeMethods.cs
using System.Runtime.InteropServices;

namespace AnonCredsNet.Interop;

internal static partial class NativeMethods
{
    private const string Library = "anoncreds";

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_get_current_error(out IntPtr errorJson);

    [LibraryImport(Library)]
    internal static partial void anoncreds_string_free(IntPtr str);

    [LibraryImport(Library)]
    internal static partial void anoncreds_buffer_free(ByteBuffer buf);

    [LibraryImport(Library)]
    internal static partial void anoncreds_object_free(UIntPtr handle);

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_object_get_json(
        UIntPtr handle,
        out ByteBuffer json
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_object_from_json(string json, out UIntPtr handle);

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_schema_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_definition_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_definition_private_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_key_correctness_proof_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_offer_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_request_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_request_metadata_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_presentation_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_presentation_request_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_revocation_registry_definition_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_revocation_registry_private_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_revocation_status_list_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_revocation_status_list_delta_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_revocation_state_from_json(
        ByteBuffer json,
        out UIntPtr handle
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_generate_nonce(out IntPtr nonce);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_schema(
        string name,
        string version,
        string issuerId,
        FfiStrList attrNames,
        out UIntPtr handle
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential_definition(
        string schemaId,
        UIntPtr schema,
        string tag,
        string issuerId,
        string signatureType,
        [MarshalAs(UnmanagedType.I1)] bool supportRevocation,
        out UIntPtr credDef,
        out UIntPtr credDefPvt,
        out UIntPtr keyProof
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential_offer(
        string schemaId,
        string credDefId,
        UIntPtr keyProof,
        out UIntPtr offer
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_link_secret(out IntPtr linkSecret);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential_request(
        string? entropy,
        string? proverDid,
        UIntPtr credDef,
        string linkSecret,
        string linkSecretId,
        UIntPtr credOffer,
        out UIntPtr request,
        out UIntPtr metadata
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential(
        UIntPtr credDef,
        UIntPtr credDefPvt,
        UIntPtr credOffer,
        UIntPtr credRequest,
        FfiStrList attrNames,
        FfiStrList attrRawValues,
        FfiStrList attrEncValues,
        IntPtr revocation,
        out UIntPtr credential
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_process_credential(
        UIntPtr credential,
        UIntPtr requestMetadata,
        string linkSecret,
        UIntPtr credDef,
        UIntPtr revRegDef,
        out UIntPtr processedCredential
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_presentation(
        UIntPtr presReq,
        FfiCredentialEntryList credentials,
        FfiCredentialProveList credentialsProve,
        FfiStrList selfAttestNames,
        FfiStrList selfAttestValues,
        string linkSecret,
        FfiObjectHandleList schemas,
        FfiStrList schemaIds,
        FfiObjectHandleList credDefs,
        FfiStrList credDefIds,
        out UIntPtr presentation
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_verify_presentation(
        UIntPtr presentation,
        UIntPtr presReq,
        FfiObjectHandleList schemas,
        FfiStrList schemaIds,
        FfiObjectHandleList credDefs,
        FfiStrList credDefIds,
        FfiObjectHandleList revRegDefs,
        FfiStrList revRegDefIds,
        FfiObjectHandleList revStatusLists,
        FfiNonrevokedIntervalOverrideList nonrevokedIntervalOverride,
        out sbyte isValid
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_revocation_registry_def(
        UIntPtr credDef,
        string issuerId,
        string tag,
        string revType,
        string config,
        string tailsPath,
        out UIntPtr revRegDef,
        out UIntPtr revRegPvt,
        out UIntPtr revStatusList
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_revocation_status_list(
        string issuerId,
        UIntPtr revRegDef,
        string timestamp,
        [MarshalAs(UnmanagedType.I1)] bool issued,
        [MarshalAs(UnmanagedType.I1)] bool revoked,
        string tailsPath,
        out UIntPtr statusList
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_update_revocation_status_list(
        UIntPtr statusList,
        string issuedJson,
        string revokedJson,
        string timestamp,
        out UIntPtr updatedList,
        out UIntPtr delta
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_revocation_state(
        IntPtr credRevInfo,
        UIntPtr revRegDef,
        UIntPtr statusList,
        string timestamp,
        string tailsPath,
        out UIntPtr revState
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_update_revocation_state(
        UIntPtr revState,
        UIntPtr revRegDef,
        UIntPtr statusListDelta,
        string timestamp,
        string tailsPath,
        out UIntPtr updatedState
    );
}
