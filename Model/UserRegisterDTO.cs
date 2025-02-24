namespace ControllersTest.Model;

public class UserRegisterDTO
{
    public string Email { get; }
    public string UserName { get; }
    public string Password { get; }

    public UserRegisterDTO(string email, string userName, string password)
    {
        Email = email;
        UserName = userName;
        Password = password;
    }
}