﻿using AuraDecor.Core.Entities;

public class Cart : BaseEntity
{
    public string UserId { get; set; }
    public ICollection<CartItem> CartItems { get; set; } = new List<CartItem>();
    public string? PaymentIntentId { get; set; }
    public Guid? DeliveryMethodId { get; set; }
    public DeliveryMethod DeliveryMethod { get; set; }

}