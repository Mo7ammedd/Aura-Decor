using System;

namespace AuraDecor.Core.Entities;

public class RefreshToken : BaseEntity
{
    public string Token { get; set; }
    public DateTime Expires { get; set; }
    public DateTime Created { get; set; } = DateTime.UtcNow;
    public string UserId { get; set; }
    public string JwtId { get; set; }    
    public bool IsRevoked { get; set; }  
    public string? ReplacedByToken { get; set; }  
    public bool IsExpired => DateTime.UtcNow >= Expires;
    public bool IsActive => !IsExpired;
}