package com.example.Marketing.graphql;

import com.example.Marketing.dto.CampaignRequest;
import com.example.Marketing.dto.CampaignResponse;
import com.example.Marketing.service.CampaignService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;

@Controller
public class CampaignGraphqlController {

    private final CampaignService campaignService;

    public CampaignGraphqlController(CampaignService campaignService) {
        this.campaignService = campaignService;
    }

    // --- MÉTODOS DE CONSULTA (existentes) ---

    @QueryMapping
    public CampaignResponse campaignById(@Argument Integer id) {
        return campaignService.getCampaignById(id);
    }

    @QueryMapping
    public Page<CampaignResponse> allCampaigns(Pageable pageable) {
        return campaignService.getAllCampaigns(pageable);
    }

    // --- MÉTODOS DE MUTACIÓN ---

    @MutationMapping
    public CampaignResponse createCampaign(@Argument @Valid CampaignRequest request) {
        return campaignService.createCampaign(request);
    }

    // --- MÉTODO DE ACTUALIZACIÓN AÑADIDO ---
    @MutationMapping
    public CampaignResponse updateCampaign(@Argument Integer id, @Argument @Valid CampaignRequest request) {
        return campaignService.updateCampaign(id, request);
    }

    // --- MÉTODO DE BORRADO AÑADIDO ---
    @MutationMapping
    public Integer deleteCampaign(@Argument Integer id) {
        return campaignService.deleteCampaign(id);
    }
}