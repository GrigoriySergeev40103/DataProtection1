using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataProtection1
{
	internal class DesCbcEncrypter : IEncrypter
	{
		public string Decrypt(string toDecrypt)
		{
			throw new NotImplementedException();
		}

		public string Encrypt(string toEncrypt)
		{
			throw new NotImplementedException();
		}

		public bool IsValidMessage(string message)
		{
			throw new NotImplementedException();
		}

		public Task LoadFromFileAsync(string fileName)
		{
			throw new NotImplementedException();
		}

		public Task SaveToFileAsync(string fileName)
		{
			throw new NotImplementedException();
		}
	}
}
