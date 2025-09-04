namespace AnonCredsNet.Models;

public class RevocationConfig
{
    public RevocationRegistryDefinition RevocationRegistryDefinition { get; set; }
    public RevocationRegistryDefinitionPrivate RevocationRegistryDefinitionPrivate { get; set; }
    public RevocationStatusList StatusList { get; set; }
    public uint RegistryIndex { get; set; }
}
