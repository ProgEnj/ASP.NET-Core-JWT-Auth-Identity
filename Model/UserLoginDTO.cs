namespace ControllersTest.Model;

public class UserLoginDTO
{
    public string Email { get; }
    public string Password { get; }

    public UserLoginDTO(string email, string password)
    {
        Email = email;
        Password = password;
    }
}