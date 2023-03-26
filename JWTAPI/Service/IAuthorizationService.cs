using JWTAPI.Models.Custom;

namespace JWTAPI.Service
{
    public interface IAuthorizationService
    {
        Task<AuthorizationResponse> DevolverToken(AuthorizationRequest authorization);
        Task<AuthorizationResponse> DevolverRefreshToken(RefreshTokenRequest refreshTokenRequest, int idUsuario);
    }
}
