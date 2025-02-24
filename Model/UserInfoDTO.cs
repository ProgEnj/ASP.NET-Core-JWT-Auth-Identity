namespace ControllersTest.Model;

public class UserInfoDTO
{
    public string Id { get; }
    public string UserName { get; }
    public string Email { get; }
    public string Token { get; }
    public string RefreshToken { get; }

    public UserInfoDTO(string id, string userName, string email, string token, string refreshToken)
    {
        Id = id;
        UserName = userName;
        Email = email;
        Token = token;
        RefreshToken = refreshToken;
    }
}
