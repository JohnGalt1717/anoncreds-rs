using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;
using AnonCredsNet.Objects;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Helpers;

internal static class AnonCredsHelpers
{
    private static bool _initialized;

    internal static void Initialize()
    {
        if (_initialized)
            return;
        // No explicit initialization in anoncreds-rs FFI, but placeholder for future use
        _initialized = true;
    }

    internal static string GetCurrentError()
    {
        var code = NativeMethods.anoncreds_get_current_error(out var ptr);
        var error =
            code == ErrorCode.Success && ptr != IntPtr.Zero
                ? Marshal.PtrToStringUTF8(ptr) ?? "Unknown error"
                : "No error details available";
        if (ptr != IntPtr.Zero)
            NativeMethods.anoncreds_string_free(ptr);
        return error;
    }

    internal static string GenerateNonce()
    {
        var code = NativeMethods.anoncreds_generate_nonce(out var ptr);
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, GetCurrentError());
        var nonce =
            Marshal.PtrToStringUTF8(ptr) ?? throw new InvalidOperationException("Null nonce");
        NativeMethods.anoncreds_string_free(ptr);
        return nonce;
    }

    // Deprecated: prefer CreateFfiObjectHandleList for object handles
    internal static FfiList CreateFfiList<T>(string json, Func<string, T> fromJson)
        where T : AnonCredsObject
    {
        var items =
            JsonSerializer.Deserialize<string[]>(json)
            ?? throw new InvalidOperationException("Invalid JSON array");
        var objectHandles = new ObjectHandle[items.Length];
        for (var i = 0; i < items.Length; i++)
        {
            var item = fromJson(items[i]);
            objectHandles[i] = new ObjectHandle { Value = item.Handle };
            item.Dispose();
        }
        var size = Marshal.SizeOf<ObjectHandle>();
        var ptr = Marshal.AllocHGlobal(items.Length * size);
        for (var i = 0; i < items.Length; i++)
        {
            Marshal.StructureToPtr(objectHandles[i], ptr + i * size, false);
        }
        return new FfiList { Data = ptr, Count = (nuint)items.Length };
    }

    internal static (FfiObjectHandleList list, T[] objects) CreateFfiObjectHandleListWithObjects<T>(
        string json,
        Func<string, T> fromJson
    )
        where T : AnonCredsObject
    {
        var items =
            JsonSerializer.Deserialize<string[]>(json)
            ?? throw new InvalidOperationException("Invalid JSON array");
        var objectHandles = new long[items.Length]; // Store long directly
        var managedObjects = new T[items.Length];

        for (var i = 0; i < items.Length; i++)
        {
            var item = fromJson(items[i]);
            managedObjects[i] = item;
            objectHandles[i] = item.Handle; // Store handle directly as long
        }

        var ptr = Marshal.AllocHGlobal(items.Length * Marshal.SizeOf<long>());
        Marshal.Copy(objectHandles, 0, ptr, items.Length);

        var list = new FfiObjectHandleList { Count = (nuint)items.Length, Data = ptr };
        return (list, managedObjects);
    }

    internal static FfiObjectHandleList CreateFfiObjectHandleList<T>(
        string json,
        Func<string, T> fromJson
    )
        where T : AnonCredsObject
    {
        var (list, _) = CreateFfiObjectHandleListWithObjects(json, fromJson);
        return list;
    }

    internal static void FreeFfiList(FfiList list)
    {
        if (list.Data != IntPtr.Zero)
            Marshal.FreeHGlobal(list.Data);
    }

    internal static ByteBuffer CreateByteBuffer(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var ptr = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, ptr, bytes.Length);
        return new ByteBuffer { Len = bytes.Length, Data = ptr };
    }

    internal static void FreeByteBuffer(ByteBuffer buffer)
    {
        if (buffer.Data != IntPtr.Zero)
            Marshal.FreeHGlobal(buffer.Data);
    }

    internal static FfiStrList CreateFfiStrList(string json)
    {
        var strings =
            JsonSerializer.Deserialize<string[]>(json)
            ?? throw new InvalidOperationException("Invalid JSON array");
        var ptrs = new IntPtr[strings.Length];
        for (var i = 0; i < strings.Length; i++)
        {
            ptrs[i] = Marshal.StringToHGlobalAnsi(strings[i]);
        }
        var listPtr = Marshal.AllocHGlobal(strings.Length * IntPtr.Size);
        Marshal.Copy(ptrs, 0, listPtr, strings.Length);
        return new FfiStrList { Count = (nuint)strings.Length, Data = listPtr };
    }

    internal static FfiStrList CreateFfiStrListFromStrings(string[] strings)
    {
        var ptrs = new IntPtr[strings.Length];
        for (var i = 0; i < strings.Length; i++)
        {
            ptrs[i] = Marshal.StringToHGlobalAnsi(strings[i]);
        }
        var listPtr = Marshal.AllocHGlobal(strings.Length * IntPtr.Size);
        Marshal.Copy(ptrs, 0, listPtr, strings.Length);
        return new FfiStrList { Count = (nuint)strings.Length, Data = listPtr };
    }

    internal static void FreeFfiStrList(FfiStrList list)
    {
        if (list.Data != IntPtr.Zero)
        {
            var count = (int)list.Count.ToUInt32(); // Convert to int for loop
            for (var i = 0; i < count; i++)
            {
                var strPtr = Marshal.ReadIntPtr(list.Data, i * IntPtr.Size);
                Marshal.FreeHGlobal(strPtr);
            }
            Marshal.FreeHGlobal(list.Data);
        }
    }

    internal static void FreeFfiObjectHandleList(FfiObjectHandleList list)
    {
        if (list.Data != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(list.Data);
        }
    }

    internal static void FreeFfiCredentialEntryList(FfiCredentialEntryList list)
    {
        if (list.Data != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(list.Data);
        }
    }

    internal static void FreeFfiCredentialProveList(FfiCredentialProveList list)
    {
        if (list.Data != IntPtr.Zero)
        {
            // Free the string pointers in each FfiCredentialProve structure
            var count = (int)list.Count.ToUInt32(); // Convert to int for loop
            for (var i = 0; i < count; i++)
            {
                var provePtr = list.Data + i * Marshal.SizeOf<FfiCredentialProve>();
                var prove = Marshal.PtrToStructure<FfiCredentialProve>(provePtr);
                if (prove.Referent != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(prove.Referent);
                }
            }
            Marshal.FreeHGlobal(list.Data);
        }
    }

    /// <summary>
    /// Verifies a presentation. Ensure the <see cref="Presentation"/> and <see cref="PresentationRequest"/> are disposed after use.
    /// </summary>
    public static bool VerifyPresentation(
        Presentation presentation,
        PresentationRequest presReq,
        string schemasJson,
        string credDefsJson,
        string schemaIdsJson,
        string credDefIdsJson,
        string? revRegDefsJson,
        string? revStatusListsJson,
        string? revRegDefIdsJson,
        string? nonRevocJson
    )
    {
        Console.WriteLine("Starting VerifyPresentation...");
        if (
            presentation == null
            || presReq == null
            || string.IsNullOrEmpty(schemasJson)
            || string.IsNullOrEmpty(credDefsJson)
            || string.IsNullOrEmpty(schemaIdsJson)
            || string.IsNullOrEmpty(credDefIdsJson)
        )
            throw new ArgumentNullException("Required parameters cannot be null or empty");
        if (presentation.Handle == 0 || presReq.Handle == 0)
            throw new ObjectDisposedException("Presentation or PresentationRequest is disposed");
        if (schemasJson.Length > 100000 || credDefsJson.Length > 100000)
            throw new ArgumentException("JSON input too large");

        Console.WriteLine("Creating FFI lists...");
        var (schemasList, schemasObjects) = CreateFfiObjectHandleListWithObjects(
            schemasJson,
            Schema.FromJson
        );
        Console.WriteLine($"Created {schemasList.Count} schemas");
        var (credDefsList, credDefsObjects) = CreateFfiObjectHandleListWithObjects(
            credDefsJson,
            CredentialDefinition.FromJson
        );
        Console.WriteLine($"Created {credDefsList.Count} credential definitions");
        var (revRegDefsList, revRegDefsObjects) = string.IsNullOrEmpty(revRegDefsJson)
            ? (
                new FfiObjectHandleList { Count = 0, Data = IntPtr.Zero },
                Array.Empty<RevocationRegistryDefinition>()
            )
            : CreateFfiObjectHandleListWithObjects(
                revRegDefsJson,
                RevocationRegistryDefinition.FromJson
            );
        var (revStatusLists, revStatusObjects) = string.IsNullOrEmpty(revStatusListsJson)
            ? (
                new FfiObjectHandleList { Count = 0, Data = IntPtr.Zero },
                Array.Empty<RevocationStatusList>()
            )
            : CreateFfiObjectHandleListWithObjects(
                revStatusListsJson,
                RevocationStatusList.FromJson
            );

        Console.WriteLine("Creating ID lists...");
        // Extract actual IDs from the JSON arrays - these must correspond to the object handles
        var schemaIds = CreateFfiStrList(schemaIdsJson);
        var credDefIds = CreateFfiStrList(credDefIdsJson);
        var revRegDefIds =
            !string.IsNullOrEmpty(revRegDefIdsJson) && revRegDefsList.Count > 0
                ? CreateFfiStrList(revRegDefIdsJson)
                : new FfiStrList { Count = 0, Data = IntPtr.Zero };

        // Debug: Print what we're passing to verification
        Console.WriteLine($"Presentation handle: {presentation.Handle}");
        Console.WriteLine($"PresentationRequest handle: {presReq.Handle}");
        Console.WriteLine($"Schemas count: {schemasList.Count}");
        Console.WriteLine($"Schema IDs count: {schemaIds.Count}");
        Console.WriteLine($"CredDefs count: {credDefsList.Count}");
        Console.WriteLine($"CredDef IDs count: {credDefIds.Count}");
        Console.WriteLine($"Schemas JSON: {schemasJson}");
        Console.WriteLine($"Schema IDs JSON: {schemaIdsJson}");
        Console.WriteLine($"CredDefs JSON: {credDefsJson}");
        Console.WriteLine($"CredDef IDs JSON: {credDefIdsJson}");

        // Empty non-revocation override list for now
        var nonRevocList = new FfiNonrevokedIntervalOverrideList { Count = 0, Data = IntPtr.Zero };

        Console.WriteLine("Calling native verify function...");
        try
        {
            // Debug: Let's verify that the object handles we're passing are valid
            Console.WriteLine($"About to call verification with:");
            Console.WriteLine($"  presentation handle: {presentation.Handle}");
            Console.WriteLine($"  presReq handle: {presReq.Handle}");
            Console.WriteLine(
                $"  schemas list count: {schemasList.Count}, data: {schemasList.Data}"
            );
            Console.WriteLine($"  schemaIds list count: {schemaIds.Count}, data: {schemaIds.Data}");
            Console.WriteLine(
                $"  credDefs list count: {credDefsList.Count}, data: {credDefsList.Data}"
            );
            Console.WriteLine(
                $"  credDefIds list count: {credDefIds.Count}, data: {credDefIds.Data}"
            );

            // Debug: Let's dump the actual memory contents of the FFI structs
            Console.WriteLine($"=== MEMORY DUMP ===");
            Console.WriteLine($"schemasList struct:");
            Console.WriteLine($"  Count: {schemasList.Count} (UIntPtr size: {UIntPtr.Size})");
            Console.WriteLine($"  Data: {schemasList.Data}");
            if (schemasList.Data != IntPtr.Zero && schemasList.Count > 0)
            {
                var handleValue = Marshal.ReadIntPtr(schemasList.Data);
                Console.WriteLine($"  First handle value: {handleValue}");
            }

            Console.WriteLine($"schemaIds struct:");
            Console.WriteLine($"  Count: {schemaIds.Count} (UIntPtr size: {UIntPtr.Size})");
            Console.WriteLine($"  Data: {schemaIds.Data}");
            if (schemaIds.Data != IntPtr.Zero && schemaIds.Count > 0)
            {
                var strPtr = Marshal.ReadIntPtr(schemaIds.Data);
                if (strPtr != IntPtr.Zero)
                {
                    var str = Marshal.PtrToStringAnsi(strPtr);
                    Console.WriteLine($"  First string: '{str}'");
                }
            }

            Console.WriteLine($"credDefsList struct:");
            Console.WriteLine($"  Count: {credDefsList.Count} (UIntPtr size: {UIntPtr.Size})");
            Console.WriteLine($"  Data: {credDefsList.Data}");
            if (credDefsList.Data != IntPtr.Zero && credDefsList.Count > 0)
            {
                var handleValue = Marshal.ReadIntPtr(credDefsList.Data);
                Console.WriteLine($"  First handle value: {handleValue}");
            }

            Console.WriteLine($"credDefIds struct:");
            Console.WriteLine($"  Count: {credDefIds.Count} (UIntPtr size: {UIntPtr.Size})");
            Console.WriteLine($"  Data: {credDefIds.Data}");
            if (credDefIds.Data != IntPtr.Zero && credDefIds.Count > 0)
            {
                var strPtr = Marshal.ReadIntPtr(credDefIds.Data);
                if (strPtr != IntPtr.Zero)
                {
                    var str = Marshal.PtrToStringAnsi(strPtr);
                    Console.WriteLine($"  First string: '{str}'");
                }
            }

            Console.WriteLine($"=== END MEMORY DUMP ===");

            // Debug: Let's also check the struct sizes and layouts
            Console.WriteLine($"=== STRUCT LAYOUT VALIDATION ===");
            Console.WriteLine($"FfiList size: {Marshal.SizeOf<FfiList>()}");
            Console.WriteLine($"FfiStrList size: {Marshal.SizeOf<FfiStrList>()}");
            Console.WriteLine($"FfiObjectHandleList size: {Marshal.SizeOf<FfiObjectHandleList>()}");
            Console.WriteLine($"UIntPtr size: {UIntPtr.Size}");
            Console.WriteLine($"IntPtr size: {IntPtr.Size}");

            // Let's manually create a struct and see how it's marshaled
            var testStruct = new FfiList { Count = (nuint)123, Data = (IntPtr)456 };
            var structSize = Marshal.SizeOf<FfiList>();
            var structPtr = Marshal.AllocHGlobal(structSize);
            try
            {
                Marshal.StructureToPtr(testStruct, structPtr, false);
                Console.WriteLine($"Test struct marshaled bytes:");
                for (int i = 0; i < structSize; i++)
                {
                    var b = Marshal.ReadByte(structPtr, i);
                    Console.Write($"{b:X2} ");
                }
                Console.WriteLine();

                // Read back the count and data
                var countBytes = new byte[UIntPtr.Size];
                Marshal.Copy(structPtr, countBytes, 0, UIntPtr.Size);
                var dataBytes = new byte[IntPtr.Size];
                Marshal.Copy(structPtr + UIntPtr.Size, dataBytes, 0, IntPtr.Size);

                Console.WriteLine($"Count bytes: {BitConverter.ToString(countBytes)}");
                Console.WriteLine($"Data bytes: {BitConverter.ToString(dataBytes)}");
            }
            finally
            {
                Marshal.FreeHGlobal(structPtr);
            }
            Console.WriteLine($"=== END STRUCT LAYOUT VALIDATION ===");

            var code = NativeMethods.anoncreds_verify_presentation(
                presentation.Handle,
                presReq.Handle,
                schemasList,
                schemaIds,
                credDefsList,
                credDefIds,
                revRegDefsList,
                revRegDefIds,
                revStatusLists,
                nonRevocList,
                out var valid
            );
            Console.WriteLine($"Native call returned with code: {code}");
            if (code != ErrorCode.Success)
                throw new AnonCredsException(code, GetCurrentError());
            Console.WriteLine(
                $"Verification result sbyte value: {valid} (converted to bool: {valid != 0})"
            );
            return valid != 0; // Convert sbyte to bool
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception in verify call: {ex.Message}");
            throw;
        }
        finally
        {
            Console.WriteLine("Cleaning up resources...");
            // Dispose managed objects after the call
            foreach (var obj in schemasObjects)
                obj?.Dispose();
            foreach (var obj in credDefsObjects)
                obj?.Dispose();
            foreach (var obj in revRegDefsObjects)
                obj?.Dispose();
            foreach (var obj in revStatusObjects)
                obj?.Dispose();

            FreeFfiObjectHandleList(schemasList);
            FreeFfiObjectHandleList(credDefsList);
            FreeFfiObjectHandleList(revRegDefsList);
            FreeFfiObjectHandleList(revStatusLists);
            FreeFfiStrList(schemaIds);
            FreeFfiStrList(credDefIds);
            if (revRegDefIds.Data != IntPtr.Zero)
                FreeFfiStrList(revRegDefIds);
            Console.WriteLine("Cleanup completed");
        }
    }

    private static string[] GeneratePlaceholderIds(long count, string prefix)
    {
        var ids = new string[count];
        for (var i = 0; i < count; i++)
        {
            ids[i] = $"{prefix}_{i}";
        }
        return ids;
    }

    private static FfiStrList ExtractIdsFromObjectArrayJson(
        string json,
        string[] idPropertyCandidates
    )
    {
        var items =
            JsonSerializer.Deserialize<string[]>(json)
            ?? throw new InvalidOperationException("Invalid JSON array");

        var ids = new string[items.Length];
        for (var i = 0; i < items.Length; i++)
        {
            var doc = JsonDocument.Parse(items[i]);
            var root = doc.RootElement;
            string? id = null;
            foreach (var prop in idPropertyCandidates)
            {
                if (root.TryGetProperty(prop, out var val) && val.ValueKind == JsonValueKind.String)
                {
                    id = val.GetString();
                    if (!string.IsNullOrEmpty(id))
                        break;
                }
            }
            if (string.IsNullOrEmpty(id))
                throw new InvalidOperationException("ID field not found in object");
            ids[i] = id!;
        }
        return CreateFfiStrList(JsonSerializer.Serialize(ids));
    }
}
