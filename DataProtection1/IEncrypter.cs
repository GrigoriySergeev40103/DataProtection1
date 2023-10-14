using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataProtection1
{
	public interface IEncrypter
	{
		public string Encrypt(string toEncrypt);
		public string Decrypt(string toDecrypt);
		
		public bool IsValidMessage(string message);

		public Task SaveToFileAsync(string fileName);
		public Task LoadFromFileAsync(string fileName);
	}
}
