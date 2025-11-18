package com.example.Marketing.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CampaignRequest {

    @NotBlank(message = "El nombre de la campaña no puede estar vacío.")
    @Size(max = 100)
    private String campaignName;

    private Boolean isActive = true;

    @NotNull(message = "El ID del usuario creador es obligatorio.")
    private Integer creatorUserId;
}