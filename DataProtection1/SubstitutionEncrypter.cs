using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DataProtection1
{
	public class SubstitutionEncrypter : IEncrypter
	{
		public struct EncryptionData
		{
			public Dictionary<string, string> Map { get; set; }
			public char FillerChar { get; set; }
		}

		protected EncryptionData _encryptionData;
		protected int _blockLength;
		protected HashSet<char> _alphabet;

		public async static Task<SubstitutionEncrypter> FromFile(string fileName)
		{
			EncryptionData encryptionData = JsonSerializer.Deserialize<EncryptionData>(await File.ReadAllTextAsync(fileName));
			SubstitutionEncrypter result = new(encryptionData)
			{
				_blockLength = encryptionData.Map.Keys.First().Length
			};

			return result;
		}

		public SubstitutionEncrypter(EncryptionData encrypterData)
		{
			_encryptionData = encrypterData;
			_blockLength = _encryptionData.Map.Keys.First().Length;

			_alphabet = ExtractAlphabet(encrypterData);
		}

		public bool IsValidMessage(string message)
		{
            foreach (char c in message)
            {
				if(!_alphabet.Contains(c))
					return false;
            }

			return true;
        }

		public string Encrypt(string toEncrypt)
		{
			int remainder = toEncrypt.Length % _blockLength;
			string sourceText = remainder switch
			{
				0 => toEncrypt,
				_ => toEncrypt + new string(_encryptionData.FillerChar, _blockLength - remainder)
			};

			StringBuilder encryptedString = new(sourceText.Length);

			for (int i = 0; i < sourceText.Length; i += _blockLength)
				encryptedString.Append(_encryptionData.Map[sourceText[i..(i + _blockLength)]]);

			return encryptedString.ToString();
		}

		public string Decrypt(string toDecrypt)
		{
			int remainder = toDecrypt.Length % _blockLength;
			string encryptedText = remainder switch
			{
				0 => toDecrypt,
				_ => toDecrypt + new string(_encryptionData.FillerChar, _blockLength - remainder)
			};

			StringBuilder decryptedString = new(encryptedText.Length);

			for (int i = 0; i < encryptedText.Length; i += _blockLength)
			{
				string decrypted = _encryptionData.Map.First(x => x.Value == encryptedText[i..(i + _blockLength)]).Key;
				decryptedString.Append(decrypted);
			}

			return decryptedString.ToString();
		}

		public async Task LoadFromFileAsync(string fileName)
		{
			FileStream jsonStream = File.Open(fileName, FileMode.Open);
			_encryptionData = await JsonSerializer.DeserializeAsync<EncryptionData>(jsonStream);
			_blockLength = _encryptionData.Map.Keys.First().Length;
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

		private static HashSet<char> ExtractAlphabet(in EncryptionData encrypterData)
		{
			HashSet<char> alphabet = new();

            foreach (string key in encrypterData.Map.Keys)
            {
                foreach (var c in key)
                {
					if(!alphabet.Contains(c))
						alphabet.Add(c);
                }
            }

			return alphabet;
        }
	}
}
