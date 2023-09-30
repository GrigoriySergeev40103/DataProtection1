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

		public SubstitutionEncrypter(string fileName)
		{
			LoadFromFile(fileName);
		}
		public SubstitutionEncrypter(EncrypterData encrypterData)
		{
			_encryptionData = encrypterData;

			var enumerator = _encryptionData.Map.Keys.GetEnumerator();
			enumerator.MoveNext();
			_blockLength = enumerator.Current.Length;
		}

		public string Encrypt(string toEncrypt)
		{
			int remainder = toEncrypt.Length % _blockLength;
			string sourceText = remainder switch
			{
				0 => toEncrypt,
				_ => toEncrypt + new string(_encryptionData.FillerChar, _blockLength - remainder)
			};

			Span<char> encryptedString = stackalloc char[sourceText.Length];

			for (int i = 0; i < sourceText.Length; i += _blockLength)
				_encryptionData.Map[sourceText[i..(i + _blockLength)]].CopyTo(encryptedString.Slice(i, i + _blockLength));

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

		public void LoadFromFile(string fileName)
		{
			string jsonContent = File.ReadAllText(fileName);
			_encryptionData = JsonSerializer.Deserialize<EncrypterData>(jsonContent);
			_blockLength = _encryptionData.Map.Keys.GetEnumerator().Current.Length;
		}
		public void SaveToFile(string fileName)
		{
			JsonSerializerOptions jsonOptions = new()
			{
				WriteIndented = true
			};

			string saveContent = JsonSerializer.Serialize(_encryptionData, jsonOptions);

			File.WriteAllText(fileName, saveContent);
		}
	}
}
