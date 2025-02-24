namespace ControllersTest.Model;

public class ResetPasswordDTO
{
    public string Id { get; }
    public string resetCode { get; }
    public string newPassword { get; }

    public ResetPasswordDTO(string email, string resetCode, string newPassword)
    {
        Id = email;
        this.resetCode = resetCode;
        this.newPassword = newPassword;
    }
}