namespace ControllersTest.Model;

public class UserInfoDTO
{
    public string UserName { get; }
    public string Email { get; }
    public string Token { get; }
    public string RefreshToken { get; }

    public UserInfoDTO(string userName, string email, string token, string refreshToken)
    {
        UserName = userName;
        Email = email;
        Token = token;
        RefreshToken = refreshToken;
    }
}
