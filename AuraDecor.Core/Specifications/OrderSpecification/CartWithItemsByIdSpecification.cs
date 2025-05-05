using AuraDecor.Core.Entities;

namespace AuraDecor.Core.Specifications.CartSpecification
{
    public class CartWithItemsByIdSpecification : BaseSpecification<Cart>
    {
        public CartWithItemsByIdSpecification(Guid cartId) 
            : base(c => c.Id == cartId)
        {
            Includes.Add(c=> c.CartItems);
        }
    }
}