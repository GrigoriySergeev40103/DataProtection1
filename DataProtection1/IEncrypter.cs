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

		public void SaveToFile(string fileName);
		public void LoadFromFile(string fileName);
	}
}
