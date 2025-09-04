namespace AnonCredsNet.Objects;

public class RevocationStatusListDelta : AnonCredsObject
{
    internal RevocationStatusListDelta(long handle)
        : base(handle) { }

    public static RevocationStatusListDelta FromJson(string json) =>
        FromJson<RevocationStatusListDelta>(json);
}
