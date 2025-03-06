namespace ControllersTest.Services;

public class Result
{
   public bool IsSuccess { get; }
   public Error Error { get; }

   protected internal Result(bool isSuccess, Error error)
   {
      // Successful operation cannot have empty error message and vice versa
      if (isSuccess && error != Error.None)
      {
         throw new InvalidOperationException();
      }
      
      if (!isSuccess && error == Error.None)
      {
         throw new InvalidOperationException();
      }

      isSuccess = isSuccess;
      Error = error;
   }

   public static Result Success() => new Result(true, Services.Error.None);
   public static Result<TValue> Success<TValue>(TValue value) => new Result<TValue>(value, true, Services.Error.None);
   public static Result Failure(Error error) => new Result(false, error);
   public static Result<TValue> Failure<TValue>(Error error) => new Result<TValue>(default(TValue), false, error);
}

public class Result<TValue> : Result
{
   private readonly TValue? _value;
   protected internal Result(TValue? value, bool isSuccess, Error error) : base(isSuccess, error)
   {
      _value = value;
   }

   public TValue Value => IsSuccess && _value != null ? _value : throw new InvalidOperationException();
   
   public static implicit operator Result<TValue>(TValue value) => Success(value);

}
