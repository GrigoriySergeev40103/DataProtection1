using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataProtection1
{
	internal class GammaEncrypter : IEncrypter
	{
        public struct EncryptionData
        {
			public int A;
			public int C;
			public int T0;
			public int B;
			public List<char> Alphabet;
        }

		protected EncryptionData _encryptionData;
		protected List<int> _randSequence = new();

		protected List<char> Alphabet => _encryptionData.Alphabet;

		public GammaEncrypter(EncryptionData encryptionData)
		{
			_encryptionData = encryptionData;
			_randSequence.Add(encryptionData.T0);
		}

        public string Decrypt(string toDecrypt)
		{
			if (_randSequence.Count < toDecrypt.Length)
				FillRandSequnce(toDecrypt.Length);

			StringBuilder result = new(toDecrypt.Length);

			for (int i = 0; i < toDecrypt.Length; i++)
			{
				int encryptedCode = Alphabet.IndexOf(toDecrypt[i]);

				int decryptedCode = encryptedCode - _randSequence[i];
				if (decryptedCode < 0)
					decryptedCode += Alphabet.Count;

				result.Append((char)decryptedCode);
			}

			return result.ToString();
		}

		public string Encrypt(string toEncrypt)
		{
			if (_randSequence.Count < toEncrypt.Length)
				FillRandSequnce(toEncrypt.Length);

			StringBuilder result = new(toEncrypt.Length);

			for (int i = 0; i < toEncrypt.Length; i++)
			{
				int sourceCode = Alphabet.IndexOf(toEncrypt[i]);

				int encryptCode = sourceCode + _randSequence[i];
				if(encryptCode >= Alphabet.Count)
					encryptCode -= Alphabet.Count;

				result.Append((char)encryptCode);
			}

			return result.ToString();
		}

		public bool IsValidMessage(string message)
		{
			for (int i = 0; i < message.Length; i++)
			{
				if (!Alphabet.Contains(message[i]))
					return false;
			}

			return true;
		}

		public Task LoadFromFileAsync(string fileName)
		{
			throw new NotImplementedException();
		}

		public Task SaveToFileAsync(string fileName)
		{
			throw new NotImplementedException();
		}

		protected void FillRandSequnce(int till)
		{
			for (int i = _randSequence.Count; i < till; i++)
			{
				int nextVal = (_encryptionData.A * _randSequence[i - 1] + _encryptionData.C) % _encryptionData.B;
				_randSequence.Add(nextVal);
			}
		}
	}
}
