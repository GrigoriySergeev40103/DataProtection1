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
		public struct EncrypterData
		{
			public Dictionary<string, string> Map { get; set; }
			public char FillerChar { get; set; }
		}

		protected EncrypterData _encryptionData;
		protected int _blockLength;
		protected HashSet<char> _alphabet;

		public EncrypterData EncryptionData => _encryptionData;

		public async static Task<SubstitutionEncrypter> FromFile(string fileName)
		{
			//EncrypterData en = JsonSerializer.Deserialize<EncrypterData>(await File.ReadAllTextAsync(fileName));


			FileStream jsonStream = File.Open(fileName, FileMode.Open);
			EncrypterData encryptionData = await JsonSerializer.DeserializeAsync<EncrypterData>(jsonStream);
			SubstitutionEncrypter result = new(encryptionData)
			{
				_blockLength = encryptionData.Map.Keys.First().Length
			};

			jsonStream.Close();

			return result;
		}

		public SubstitutionEncrypter(EncrypterData encrypterData)
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
			_encryptionData = await JsonSerializer.DeserializeAsync<EncrypterData>(jsonStream);
			var enumerator = _encryptionData.Map.Keys.GetEnumerator();
			enumerator.MoveNext();
			_blockLength = enumerator.Current.Length;
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

		private static HashSet<char> ExtractAlphabet(in EncrypterData encrypterData)
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
