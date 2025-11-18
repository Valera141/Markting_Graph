package com.example.Marketing.service;

import com.example.Marketing.dto.CampaignRequest;
import com.example.Marketing.dto.CampaignResponse;
import com.example.Marketing.exception.ResourceNotFoundException;
import com.example.Marketing.mapper.CampaignMapper;
import com.example.Marketing.model.Campaign;
import com.example.Marketing.model.User;
import com.example.Marketing.repository.CampaignRepository;
import com.example.Marketing.repository.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import java.time.OffsetDateTime;

@Service
public class CampaignServiceImpl implements CampaignService {

    private final CampaignRepository campaignRepository;
    private final UserRepository userRepository; // <-- 1. Añade el repositorio de User

    // 2. Actualiza el constructor
    public CampaignServiceImpl(CampaignRepository campaignRepository, UserRepository userRepository) {
        this.campaignRepository = campaignRepository;
        this.userRepository = userRepository;
    }

    @Override
    public Page<CampaignResponse> getAllCampaigns(Pageable pageable) {
        @SuppressWarnings("null")
        Page<Campaign> campaignPage = campaignRepository.findAll(pageable);
        return campaignPage.map(CampaignMapper::toResponse);
    }

    @Override
    public CampaignResponse getCampaignById(Integer id) {
        @SuppressWarnings("null")
        Campaign campaign = campaignRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Campaña no encontrada con id: " + id));
        return CampaignMapper.toResponse(campaign);
    }

    // --- 3. IMPLEMENTA EL NUEVO MÉTODO ---
    // (Esta lógica es idéntica a la del maestro)
    @Override
    public CampaignResponse createCampaign(CampaignRequest request) {
        // 1. Busca la entidad 'User' relacionada usando el ID
        @SuppressWarnings("null")
        User creator = userRepository.findById(request.getCreatorUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Usuario creador no encontrado con id: " + request.getCreatorUserId()));

        // 2. Convierte el DTO a la entidad Campaign
        Campaign newCampaign = CampaignMapper.toEntity(request);
        
        // 3. Asigna las entidades y valores calculados
        newCampaign.setCreatorUser(creator);
        newCampaign.setCreationDate(OffsetDateTime.now());

        // 4. Guarda la nueva entidad en la BD
        Campaign savedCampaign = campaignRepository.save(newCampaign);

        // 5. Convierte la entidad guardada a un DTO de respuesta y devuélvelo
        return CampaignMapper.toResponse(savedCampaign);
    }

    // --- 4. MÉTODO DE ACTUALIZACIÓN AÑADIDO ---
    @Override
    public CampaignResponse updateCampaign(Integer id, CampaignRequest request) {
        // 1. Busca la campaña existente o falla
        @SuppressWarnings("null")
        Campaign existingCampaign = campaignRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Campaña no encontrada con id: " + id));

        // 2. Busca el usuario (para asegurar que el ID del DTO es válido y actualizarlo)
        @SuppressWarnings("null")
        User creator = userRepository.findById(request.getCreatorUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Usuario creador no encontrado con id: " + request.getCreatorUserId()));
        
        // 3. Usa el Mapper para copiar los datos simples (nombre, activo)
        CampaignMapper.copyToEntity(request, existingCampaign);
        
        // 4. Actualiza la relación del usuario
        existingCampaign.setCreatorUser(creator);

        // 5. Guarda la entidad actualizada
        Campaign updatedCampaign = campaignRepository.save(existingCampaign);

        // 6. Devuelve el DTO de respuesta
        return CampaignMapper.toResponse(updatedCampaign);
    }

    // --- 5. MÉTODO DE BORRADO AÑADIDO ---
    @SuppressWarnings("null")
    @Override
    public Integer deleteCampaign(Integer id) {
        // 1. Verifica si la campaña existe o falla
        if (!campaignRepository.existsById(id)) {
            throw new ResourceNotFoundException("Campaña no encontrada con id: " + id);
        }
        
        // 2. Bórrala
        campaignRepository.deleteById(id);
        
        // 3. Devuelve el ID
        return id;
    }
}