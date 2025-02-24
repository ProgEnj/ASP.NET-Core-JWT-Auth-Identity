namespace ControllersTest.Model;

public class ForgotPasswordDTO
{
    public string Email { get; }
    
    public ForgotPasswordDTO(string email)
    {
        Email = email;
    }
}