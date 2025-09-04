using System.Text.Json;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;
using Xunit;

namespace AnonCredsNet.Tests
{
    public class SimpleVerificationTest
    {
        [Fact]
        public void CanCreateAndVerifySimplePresentation()
        {
            // Test parameters (matching Python test structure)
            var issuerId = "mock:uri";
            var schemaId = "mock:uri";
            var credDefId = "mock:uri";
            var entropy = "entropy";

            // Create schema (exact match to Python test)
            var schema = Schema.Create(
                "schema name",
                "1.0.0",
                issuerId,
                JsonSerializer.Serialize(new[] { "name", "age", "sex", "height" })
            );

            // Create credential definition with revocation support disabled temporarily
            // (Python test structure but without revocation until C# API is complete)
            var (credDef, credDefPrivate, keyProof) = CredentialDefinition.Create(
                schemaId,
                issuerId,
                schema,
                "tag",
                "CL",
                "{\"support_revocation\": false}"
            );

            // Create link secret (exact match to Python test)
            var linkSecret = LinkSecret.Create();
            var linkSecretId = "default";

            // Create credential offer (exact match to Python test)
            var credOffer = CredentialOffer.Create(schemaId, credDefId, keyProof);

            // Create credential request (exact match to Python test)
            var (credRequest, metadata) = CredentialRequest.Create(
                credDef,
                linkSecret,
                linkSecretId,
                credOffer,
                entropy
            );

            Console.WriteLine("=== C# to Python Comparison Debug ===");
            Console.WriteLine($"Schema ID: {schemaId}");
            Console.WriteLine($"CredDef ID: {credDefId}");
            Console.WriteLine($"Issuer ID: {issuerId}");

            // Create credential values (exact match to Python test)
            var credValues = JsonSerializer.Serialize(
                new Dictionary<string, string>
                {
                    ["sex"] = "male",
                    ["name"] = "Alex",
                    ["height"] = "175",
                    ["age"] = "28",
                }
            );

            Console.WriteLine($"Credential values: {credValues}");

            // Issue credential without revocation (simplified for now)
            var client = new AnonCredsClient();
            var credential = client.IssueCredential(
                credDef,
                credDefPrivate,
                credOffer,
                credRequest,
                credValues,
                null, // no revocation registry ID
                null, // no tails path
                null // no revocation status list
            );

            // Process credential (binds to link secret) — required before using in presentation
            var processedCredential = credential.Process(metadata, linkSecret, credDef, null);

            // Create presentation request (simplified to only use credential attributes for now)
            var nonce = AnonCredsClient.GenerateNonce();
            var presReqJson = JsonSerializer.Serialize(
                new
                {
                    nonce = nonce,
                    name = "pres_req_1",
                    version = "0.1",
                    requested_attributes = new
                    {
                        attr1_referent = new { name = "name", issuer_id = issuerId },
                        attr2_referent = new { name = "sex" },
                        // Removed attr3_referent (phone) to match simplified test
                        attr4_referent = new { names = new[] { "name", "height" } },
                    },
                    requested_predicates = new
                    {
                        predicate1_referent = new
                        {
                            name = "age",
                            p_type = ">=",
                            p_value = 18,
                        },
                    },
                }
            );
            var presReq = PresentationRequest.FromJson(presReqJson);

            // Create presentation credentials (matching Python test structure)
            var presentCredentials = JsonSerializer.Serialize(
                new[]
                {
                    new
                    {
                        credential = processedCredential.ToJson(),
                        timestamp = (int?)null,
                        rev_state = (string?)null,
                    },
                }
            );

            // Create presentation (exact match to Python test)
            var schemasJson = JsonSerializer.Serialize(new[] { schema.ToJson() });
            var credDefsJson = JsonSerializer.Serialize(new[] { credDef.ToJson() });
            var schemaIdsJson = JsonSerializer.Serialize(new[] { schemaId });
            var credDefIdsJson = JsonSerializer.Serialize(new[] { credDefId });

            // Self-attested attributes (empty since we removed phone temporarily)
            var selfAttestedAttrs = JsonSerializer.Serialize(new Dictionary<string, string>());

            Console.WriteLine("Creating presentation...");
            var (presentation, _, _, _, _, _, _, _, _, _) = client.CreatePresentation(
                presReq,
                presentCredentials,
                selfAttestedAttrs,
                linkSecret,
                schemasJson,
                credDefsJson,
                schemaIdsJson,
                credDefIdsJson,
                null,
                null
            );

            // Verify presentation (exact match to Python test structure but without revocation)
            Console.WriteLine("Verifying presentation...");
            var verified = client.VerifyPresentation(
                presentation,
                presReq,
                schemasJson,
                credDefsJson,
                schemaIdsJson,
                credDefIdsJson,
                null, // no revocation registry definitions
                null, // no revocation registry IDs
                null // no revocation status lists
            );

            Console.WriteLine($"Verification result: {verified}");
            Assert.True(verified, "Presentation verification should succeed");

            Console.WriteLine("Non-revocation test completed successfully!");

            // Cleanup
            schema.Dispose();
            credDef.Dispose();
            credDefPrivate.Dispose();
            keyProof.Dispose();
            // linkSecret is a string, no Dispose
            credOffer.Dispose();
            credRequest.Dispose();
            metadata.Dispose();
            credential.Dispose();
            processedCredential.Dispose();
            presReq.Dispose();
            presentation.Dispose();
        }
    }
}
