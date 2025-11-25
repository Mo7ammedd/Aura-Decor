namespace AuraDecor.APIs.Dtos.Incoming;

public class TwoFactorDto
{
    public string Code { get; set; }
}

public class TwoFactorLoginDto
{
    public string Email { get; set; }
    public string Password { get; set; }
    public string Code { get; set; }
}
