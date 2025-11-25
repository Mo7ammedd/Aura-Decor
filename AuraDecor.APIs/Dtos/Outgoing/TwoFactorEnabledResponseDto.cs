namespace AuraDecor.APIs.Dtos.Outgoing;

public class TwoFactorEnabledResponseDto
{
    public string SharedKey { get; set; }
    public string AuthenticatorUri { get; set; }
    public string QrCodeBase64 { get; set; }
}
