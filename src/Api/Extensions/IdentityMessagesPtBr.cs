using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace Api.Extensions
{
    public class IdentityMessagesPtBr: IdentityErrorDescriber
    {
        public override IdentityError DefaultError()
        {
            return new IdentityError(){Code = nameof(DefaultError), Description = "Ocorreu um erro desconhecido."};
        }
    }
}
