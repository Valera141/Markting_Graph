package com.example.Marketing.service;

import com.example.Marketing.dto.CampaignRequest; // <-- AÑADIDO
import com.example.Marketing.dto.CampaignResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface CampaignService {

    Page<CampaignResponse> getAllCampaigns(Pageable pageable);
    
    CampaignResponse getCampaignById(Integer id);
    
    CampaignResponse createCampaign(CampaignRequest request);

    CampaignResponse updateCampaign(Integer id, CampaignRequest request);

    Integer deleteCampaign(Integer id);
}