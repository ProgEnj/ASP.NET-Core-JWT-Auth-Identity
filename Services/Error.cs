namespace ControllersTest.Services;

public class Error : IEquatable<Error>
{
    public string Message { get; }
    public static readonly Error None = new Error(string.Empty);

    public Error(string message)
    {
        Message = message;
    }
    
    public bool Equals(Error? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return Message == other.Message;
    }

    public override bool Equals(object? obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != GetType()) return false;
        return Equals((Error)obj);
    }

    public override int GetHashCode()
    {
        return Message.GetHashCode() * 397;
    }

    public static bool operator ==(Error? a, Error? b)
    {
        if(ReferenceEquals(a, b)) { return true; }
        if(ReferenceEquals(a, null)) { return false; }
        if(ReferenceEquals(b, null)) { return false; }

        return a.Equals(b);
    }
    
    public static bool operator !=(Error? a, Error? b)
    {
        return !(a == b);
    }
}