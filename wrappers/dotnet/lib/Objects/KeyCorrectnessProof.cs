namespace AnonCredsNet.Objects;

public class KeyCorrectnessProof : AnonCredsObject
{
    internal KeyCorrectnessProof(UIntPtr handle)
        : base(handle) { }

    internal static KeyCorrectnessProof FromJson(string json) =>
        FromJson<KeyCorrectnessProof>(json);
}
