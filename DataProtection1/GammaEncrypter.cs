using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DataProtection1
{
	internal class GammaEncrypter : IEncrypter
	{
        public struct EncryptionData
        {
			public int A { get; set; }
			public int C { get; set; }
			public int T0 { get; set; }
			public int B { get; set; }
			public List<char> Alphabet { get; set; }
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

			int lastVal = _encryptionData.T0;
			for (int i = 0; i < toEncrypt.Length; i++)
			{
				int sourceCode = Alphabet.IndexOf(toEncrypt[i]);

				int nextVal = (_encryptionData.A * lastVal + _encryptionData.C) % _encryptionData.B;
				lastVal = nextVal;

				int encryptCode = sourceCode + nextVal;
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

		public async Task LoadFromFileAsync(string fileName)
		{
			FileStream jsonStream = File.Open(fileName, FileMode.Open);
			_encryptionData = await JsonSerializer.DeserializeAsync<EncryptionData>(jsonStream);
			_randSequence.Add(_encryptionData.T0);
		}

		public async Task SaveToFileAsync(string fileName)
		{
			JsonSerializerOptions jsonOptions = new()
			{
				WriteIndented = true
			};

			string saveContent = JsonSerializer.Serialize(_encryptionData, jsonOptions);

			await File.WriteAllTextAsync(fileName, saveContent);
		}

		protected void FillRandSequnce(int till)
		{
			for (int i = _randSequence.Count; i < till; i++)
			{
				int nextVal = (_encryptionData.A * _randSequence[i - 1] + _encryptionData.C) % _encryptionData.B;
				_randSequence.Add(nextVal);
			}
		}

		public async static Task<GammaEncrypter> FromFile(string fileName)
		{
			EncryptionData encryptionData = JsonSerializer.Deserialize<EncryptionData>(await File.ReadAllTextAsync(fileName));
			GammaEncrypter result = new(encryptionData);

			return result;
		}
	}
}
