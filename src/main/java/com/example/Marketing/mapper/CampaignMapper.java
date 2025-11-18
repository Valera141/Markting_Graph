package com.example.Marketing.mapper;

import com.example.Marketing.dto.CampaignRequest;
import com.example.Marketing.dto.CampaignResponse;
import com.example.Marketing.dto.UserResponse;
import com.example.Marketing.model.Campaign;
import com.example.Marketing.model.User;

public class CampaignMapper {
    public static void copyToEntity(CampaignRequest dto, Campaign entity) {
        if (dto == null || entity == null) {
            return;
        }
        entity.setCampaignName(dto.getCampaignName());
        entity.setIsActive(dto.getIsActive());
    }

    public static Campaign toEntity(CampaignRequest request) {
        if (request == null) {
            return null;
        }
        Campaign campaign = new Campaign();
        campaign.setCampaignName(request.getCampaignName());
        campaign.setIsActive(request.getIsActive());
        
        return campaign;
    }

    public static CampaignResponse toResponse(Campaign campaign) {
        if (campaign == null) {
            return null;
        }

        CampaignResponse dto = new CampaignResponse();
        dto.setCampaignId(campaign.getCampaignId());
        dto.setCampaignName(campaign.getCampaignName());
        dto.setIsActive(campaign.getIsActive());
        dto.setCreationDate(campaign.getCreationDate());
        
        dto.setCreatorUser(toUserResponse(campaign.getCreatorUser()));

        return dto;
    }

    private static UserResponse toUserResponse(User user) {
        if (user == null) {
            return null;
        }

        UserResponse userDto = new UserResponse();
        userDto.setUserId(user.getUserId());
        userDto.setFullName(user.getFullName());
        
        return userDto;
    }
}