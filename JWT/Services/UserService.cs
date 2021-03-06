using JWT.Models;

namespace JWT.Services;

public interface IUserService
{
    User? GetUser(string username);
    User[] GetUsers();
    void AddUser(User user);
}

public class UserService : IUserService
{
    private readonly List<User> _users;

    public UserService()
    {
        _users = new List<User>();
        AddUser(new User("kelly", new [] { Role.Admin, Role.User}));
        AddUser(new User("john", new [] { Role.Admin }));
        AddUser(new User("adam", new [] { Role.User }));
    }

    public User[] GetUsers()
    {
        return _users.ToArray();
    }

    public User? GetUser(string username)
    {
        return _users.FirstOrDefault(user => user.Username == username);
    }

    public void AddUser(User user)
    {
        _users.Add(user);
    }
}