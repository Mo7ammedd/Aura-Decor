﻿using AuraDecor.Core.Entities;
using AuraDecor.Core.Repositories.Contract;
using AuraDecor.Core.Services.Contract;
using AutoMapper;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Stripe;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AuraDecor.Core.Entities.Enums;

namespace AuraDecor.Servicies
{
    public class PaymentService : IPaymentService
    {
        public readonly IUnitOfWork _unitOfWork;
        private readonly IConfiguration _config;
        private readonly ILogger<PaymentService> _logger;

        public PaymentService(IUnitOfWork unitOfWork, IConfiguration config, ILogger<PaymentService> logger)
        {
            _unitOfWork = unitOfWork;
            _config = config;
            _logger = logger;
            StripeConfiguration.ApiKey = _config["Stripe:SecretKey"];
        }

        public async Task<PaymentIntent> CreateOrUpdatePaymentIntentAysnc(Guid CartId)
        {
            var cart = await _unitOfWork.Repository<Cart>().GetByIdAsync(CartId);

            if (cart == null)
            {
                throw new Exception("Cart not found");
            }
            
            if (!cart.CartItems.Any())
            {
                throw new Exception("Empty cart");
            }

            decimal deliveryCost = 0;

            if (cart.DeliveryMethodId.HasValue)
            {
                var delivery = await _unitOfWork.Repository<DeliveryMethod>().GetByIdAsync(cart.DeliveryMethodId.Value);
                if (delivery != null)
                {
                    deliveryCost = delivery.Cost;
                }
            }

            var amount = cart.CartItems.Sum(i => i.Quantity * i.Furniture.Price) + deliveryCost;
            long amountInCents = (long)(amount * 100);

            var service = new PaymentIntentService();
            PaymentIntent intent;

            var metadata = new Dictionary<string, string>
            {
                { "CartId", cart.Id.ToString() },
                { "UserId", cart.UserId }
            };

            if (string.IsNullOrEmpty(cart.PaymentIntentId))
            {
                var createOptions = new PaymentIntentCreateOptions
                {
                    Amount = amountInCents,
                    Currency = "usd",
                    PaymentMethodTypes = new List<string> { "card" },
                    Metadata = metadata,
                    Description = $"Order payment for cart {cart.Id}"
                };

                intent = await service.CreateAsync(createOptions);
                _logger.LogInformation($"Created new payment intent {intent.Id} for cart {CartId}");

                cart.PaymentIntentId = intent.Id;
                await _unitOfWork.Repository<Cart>().UpdateAsync(cart);
                await _unitOfWork.CompleteAsync();
            }
            else
            {
                var updateOptions = new PaymentIntentUpdateOptions
                {
                    Amount = amountInCents,
                    Metadata = metadata
                };

                intent = await service.UpdateAsync(cart.PaymentIntentId, updateOptions);
                _logger.LogInformation($"Updated payment intent {intent.Id} for cart {CartId}");
            }

            return intent;
        }

        public async Task<PaymentIntentResponse> GetPaymentIntentClientSecret(Guid CartId)
        {
            var cart = await _unitOfWork.Repository<Cart>().GetByIdAsync(CartId);
            
            if (cart == null)
            {
                throw new Exception("Cart not found");
            }
            
            if (string.IsNullOrEmpty(cart.PaymentIntentId))
            {
                var intent = await CreateOrUpdatePaymentIntentAysnc(CartId);
                return new PaymentIntentResponse
                {
                    ClientSecret = intent.ClientSecret,
                    PaymentIntentId = intent.Id
                };
            }
            
            try 
            {
                var service = new PaymentIntentService();
                var intent = await service.GetAsync(cart.PaymentIntentId);
                
                return new PaymentIntentResponse
                {
                    ClientSecret = intent.ClientSecret,
                    PaymentIntentId = intent.Id
                };
            }
            catch (StripeException ex) 
            {
                if (ex.StripeError.Code == "resource_missing")
                {
                    _logger.LogWarning($"Payment intent {cart.PaymentIntentId} no longer exists, creating new one");
                    cart.PaymentIntentId = null;
                    await _unitOfWork.Repository<Cart>().UpdateAsync(cart);
                    await _unitOfWork.CompleteAsync();
                    var intent = await CreateOrUpdatePaymentIntentAysnc(CartId);
                    return new PaymentIntentResponse
                    {
                        ClientSecret = intent.ClientSecret,
                        PaymentIntentId = intent.Id
                    };
                }
                
                throw new Exception($"Stripe error: {ex.Message}");
            }
        }

        public async Task<bool> UpdateOrderPaymentSucceeded(string paymentIntentId)
        {
            var cart = await _unitOfWork.Repository<Cart>()
                .FindAsync(x => x.PaymentIntentId == paymentIntentId);
                
            if (cart == null) 
            {
                return false;
            }
            
            var order = await _unitOfWork.Repository<Order>()
                .FindAsync(x => x.PaymentIntentId == paymentIntentId);
                
            if (order == null)
            {
                return false;
            }

            order.PaymentStatus = PaymentStatus.Succeeded;
            order.Status = OrderStatus.Processing;
            
            await _unitOfWork.CompleteAsync();
            _logger.LogInformation($"Order {order.Id} payment succeeded for payment intent {paymentIntentId}");
            return true;
        }

        public async Task<bool> UpdateOrderPaymentFailed(string paymentIntentId)
        {
            var order = await _unitOfWork.Repository<Order>()
                .FindAsync(x => x.PaymentIntentId == paymentIntentId);
                
            if (order == null)
            {
                return false;
            }
            
            order.PaymentStatus = PaymentStatus.Failed;
            await _unitOfWork.CompleteAsync();
            return true;
        }
        
        public async Task<PaymentStatus> VerifyPaymentStatus(string paymentIntentId)
        {
            if (string.IsNullOrEmpty(paymentIntentId))
            {
                return PaymentStatus.Failed;
            }
            
            var service = new PaymentIntentService();
            var paymentIntent = await service.GetAsync(paymentIntentId);
            
            if (paymentIntent == null)
            {
                return PaymentStatus.Failed;
            }
            
            _logger.LogInformation($"Payment intent {paymentIntentId} status: {paymentIntent.Status}");
            
            switch (paymentIntent.Status)
            {
                case "succeeded":
                    return PaymentStatus.Succeeded;
                    
                case "processing":
                    // Still processing, maintain pending status
                    return PaymentStatus.Pending;
                    
                case "requires_payment_method":
                case "requires_confirmation":
                case "requires_action":
                case "requires_capture":
                    return PaymentStatus.Pending;
                    
                case "canceled":
                case "failed":
                default:
                    return PaymentStatus.Failed;
            }
        }
        
        public async Task<RefundResponse> CreateRefundAsync(Guid orderId, decimal amount = 0, string reason = null)
        {
            // Get the order
            var order = await _unitOfWork.Repository<Order>().GetByIdAsync(orderId);
            
            if (order == null)
            {
                return new RefundResponse { 
                    Success = false, 
                    Error = "Order not found" 
                };
            }
            
            if (order.PaymentStatus != PaymentStatus.Succeeded)
            {
                return new RefundResponse { 
                    Success = false, 
                    Error = $"Order payment status is {order.PaymentStatus}" 
                };
            }
            
            // Check if we have a payment intent ID
            if (string.IsNullOrEmpty(order.PaymentIntentId))
            {
                return new RefundResponse { 
                    Success = false, 
                    Error = "No payment intent associated with this order" 
                };
            }
            
            var piService = new PaymentIntentService();
            var paymentIntent = await piService.GetAsync(order.PaymentIntentId);
            
            if (paymentIntent == null || paymentIntent.Status != "succeeded")
            {
                return new RefundResponse { 
                    Success = false, 
                    Error = "Payment has not been successfully processed" 
                };
            }
            
            string chargeId = paymentIntent.LatestChargeId;
            if (string.IsNullOrEmpty(chargeId))
            {
                return new RefundResponse { 
                    Success = false, 
                    Error = "No charge found for this payment" 
                };
            }
            
            var refundOptions = new RefundCreateOptions
            {
                Charge = chargeId,
                Reason = string.IsNullOrEmpty(reason) ? "requested_by_customer" : reason
            };
            
            if (amount > 0)
            {
                refundOptions.Amount = (long)(amount * 100);
            }
            
            var refundService = new RefundService();
            var refund = await refundService.CreateAsync(refundOptions);
            
            if (refund.Status == "succeeded")
            {
                if (!refundOptions.Amount.HasValue)
                {
                    order.Status = OrderStatus.Cancelled;
                    await _unitOfWork.CompleteAsync();
                    _logger.LogInformation($"Order {orderId} cancelled due to full refund");
                }
                else
                {
                    _logger.LogInformation($"Partial refund processed for order {orderId}");
                }
            }
            
            decimal refundAmount = refund.Amount / 100m;
            _logger.LogInformation($"Refund {refund.Id} created for order {orderId}, amount: {refundAmount}");
            
            return new RefundResponse
            {
                Success = true,
                RefundId = refund.Id,
                Amount = refundAmount
            };
        }
    }
}
