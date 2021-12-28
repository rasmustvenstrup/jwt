namespace JWT.Models;

public class User
{
    public Guid Id { get; }

    public string Username { get; }

    public Role[] Roles { get; }

    public User(string username, Role[] roles)
    {
        Id = Guid.NewGuid();
        Username = username;
        Roles = roles;
    }
}