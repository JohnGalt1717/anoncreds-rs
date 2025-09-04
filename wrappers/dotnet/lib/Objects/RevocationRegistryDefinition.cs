namespace AnonCredsNet.Objects;

public class RevocationRegistryDefinition : AnonCredsObject
{
    internal RevocationRegistryDefinition(long handle)
        : base(handle) { }

    public static RevocationRegistryDefinition FromJson(string json) =>
        FromJson<RevocationRegistryDefinition>(json);
}
