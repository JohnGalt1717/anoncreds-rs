namespace AnonCredsNet.Objects;

public class RevocationStatusListDelta : AnonCredsObject
{
    internal RevocationStatusListDelta(UIntPtr handle)
        : base(handle) { }

    public static RevocationStatusListDelta FromJson(string json) =>
        FromJson<RevocationStatusListDelta>(json);
}
