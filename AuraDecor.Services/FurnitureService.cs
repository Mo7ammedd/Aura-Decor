﻿using AuraDecor.Core.Entities;
using AuraDecor.Core.Repositories.Contract;
using AuraDecor.Core.Services.Contract;
using AuraDecor.Repositoriy.Migrations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AuraDecor.Core.Specifications.ProductSpecification;

namespace AuraDecor.Servicies
{
    public class FurnitureService : IFurnitureService
    {
        private readonly IUnitOfWork _unitOfWork;

        public FurnitureService(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        public async Task<IReadOnlyList<Furniture>> SearchFurnitureAsync(string searchTerm)
        {
            var spec = new FurnitureSearchSpec(searchTerm);
            return await _unitOfWork.Repository<Furniture>().GetAllWithSpecAsync(spec);
        }

        public async Task AddFurnitureAsync(Furniture furniture)
        {
            _unitOfWork.Repository<Furniture>().Add(furniture);
            await _unitOfWork.CompleteAsync();
        }

        public async Task DeleteFurnitureAsync(Furniture furniture)
        {
             _unitOfWork.Repository<Furniture>().DeleteAsync(furniture);
            await _unitOfWork.CompleteAsync();
        }

        public async Task<IReadOnlyList<Furniture>> GetAllFurnitureAsync(string sort, Guid? brandId, Guid? categoryId)
        {
            var spec = new FurnitureWithCategoryAndBrandSpec(sort, brandId, categoryId);
            return await _unitOfWork.Repository<Furniture>().GetAllWithSpecAsync(spec);
        }

        public async Task<Furniture> GetFurnitureByIdAsync(Guid id)
        {
            var spec = new FurnitureWithCategoryAndBrandSpec(id);
            return await _unitOfWork.Repository<Furniture>().GetWithSpecAsync(spec);
        }

        public async Task UpdateFurnitureAsync(Furniture furniture)
        {
            _unitOfWork.Repository<Furniture>().UpdateAsync(furniture);
            await _unitOfWork.CompleteAsync();
        }
    }
}
