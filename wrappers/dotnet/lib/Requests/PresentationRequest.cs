using AnonCredsNet.Objects;

namespace AnonCredsNet.Requests;

public sealed class PresentationRequest : AnonCredsObject
{
    internal PresentationRequest(UIntPtr handle)
        : base(handle) { }

    public static PresentationRequest FromJson(string json) =>
        AnonCredsObject.FromJson<PresentationRequest>(json);
}
