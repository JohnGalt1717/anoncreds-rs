namespace AnonCredsNet.Objects;

public class RevocationRegistryPrivate : AnonCredsObject
{
    internal RevocationRegistryPrivate(UIntPtr handle)
        : base(handle) { }

    public static RevocationRegistryPrivate FromJson(string json) =>
        FromJson<RevocationRegistryPrivate>(json);
}
