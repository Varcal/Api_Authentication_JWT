using System.ComponentModel.DataAnnotations;

namespace Api.Models
{
    public class RegisterUserViewModel
    {
        [Required(ErrorMessage = "O campo {0} é obigatório")]
        [EmailAddress(ErrorMessage = "O campo {0} está em formato inválido")]
        public string Email { get; set; }

        [Required(ErrorMessage = "O campo {0} é obigatório")]
        [StringLength(100, ErrorMessage = "Campo {0} precisa ter entre {2} e {1} caractéres", MinimumLength = 6)]
        public string Password { get; set; }

        [Compare("Password", ErrorMessage = "As senhas não conferem")]
        public string ConfirmPassword { get; set; }
    }

    public class LoginUserViewModel
    {
        [Required(ErrorMessage = "O campo {0} é obigatório")]
        [EmailAddress(ErrorMessage = "O campo {0} está em formato inválido")]
        public string Email { get; set; }

        [Required(ErrorMessage = "O campo {0} é obigatório")]
        [StringLength(100, ErrorMessage = "Campo {0} precisa ter entre {2} e {1} caractéres", MinimumLength = 6)]
        public string Password { get; set; }
    }
}
